/**
 * server.js
 * - Express + Socket.IO signaling server
 * - Redis-backed room store + socket.io redis adapter
 * - JWT tokens with jti stored in Redis (revocable)
 * - Minimal admin UI served at /admin (single-file)
 *
 * Notes:
 *  - This uses the redis v4 client (node-redis).
 *  - Make sure REDIS_URL is set in env.
 */

import express from "express";
import http from "http";
import { Server } from "socket.io";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { createClient } from "redis";
import { createAdapter } from "@socket.io/redis-adapter";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));


const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const TOKEN_TTL = parseInt(process.env.TOKEN_TTL_SECONDS || "3600", 10);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";
const TURN_SERVER_URL = process.env.TURN_SERVER_URL || null;

async function start() {
  // Create Redis client for data (and pub/sub for socket adapter)
  const redisClient = createClient({ url: REDIS_URL });
  redisClient.on("error", (err) => console.error("Redis client error", err));
  await redisClient.connect();

  // pub/sub clients for socket.io adapter
  const pubClient = createClient({ url: REDIS_URL });
  const subClient = pubClient.duplicate();
  await pubClient.connect();
  await subClient.connect();

  // Express health + REST endpoints
  app.get("/", (req, res) => res.send("Casting API + Redis + JWT (revocable)"));

  /* -------------------------
     Redis data schema (simple)
     - rooms (set): contains room ids
     - room:{roomId} (hash): {id, ownerId, createdAt, ttlSeconds, metadata(json)}
     - room:{roomId}:participants (set): userIds
     - token:{jti} (string): JSON string {roomId,userId,role} with TTL = token expiry
     -------------------------- */

  // Utility: create short-ish random room id
  function makeRoomId(len = 7) {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    let out = "";
    for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
    return out;
  }

  // JWT helpers (create jti and store token server-side)
  async function signToken({ roomId, userId, role = "participant", expiresIn = TOKEN_TTL }) {
    const jti = uuidv4();
    const payload = { roomId, userId, role, jti };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn });
    // store token metadata in redis with TTL (so we can revoke or validate server-side)
    await redisClient.setEx(`token:${jti}`, expiresIn, JSON.stringify({ roomId, userId, role }));
    return { token, jti };
  }

  async function verifyTokenAndPayload(token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (!payload || !payload.jti) throw new Error("Invalid token payload");
      // check token exists in redis and not revoked
      const key = `token:${payload.jti}`;
      const stored = await redisClient.get(key);
      if (!stored) throw new Error("Token not found / revoked / expired");
      // success: return decoded payload
      return payload;
    } catch (err) {
      throw err;
    }
  }

  // REST: create room
  app.post("/rooms", async (req, res) => {
    try {
      const { ownerId = null, ttlSeconds = 3600, metadata = {} } = req.body || {};
      const roomId = makeRoomId();
      const createdAt = Date.now();
      const roomKey = `room:${roomId}`;
      await redisClient.hSet(roomKey, {
        id: roomId,
        ownerId: ownerId || "",
        createdAt: String(createdAt),
        ttlSeconds: String(ttlSeconds),
        metadata: JSON.stringify(metadata)
      });
      // Add to rooms set
      await redisClient.sAdd("rooms", roomId);
      // Set room expiry (makes Redis remove it automatically). We'''ll also emit if needed.
      await redisClient.expire(roomKey, ttlSeconds);
      // create participants set with same TTL
      const participantsKey = `room:${roomId}:participants`;
      await redisClient.sAdd(participantsKey); // create empty set
      await redisClient.expire(participantsKey, ttlSeconds);

      res.json({ ok: true, room: { id: roomId, createdAt, ttlSeconds, ownerId, metadata } });
    } catch (err) {
      console.error("create room err", err);
      res.status(500).json({ ok: false, error: "server error" });
    }
  });

  // REST: list rooms
  app.get("/rooms", async (req, res) => {
    try {
      const roomIds = await redisClient.sMembers("rooms");
      const out = [];
      for (const id of roomIds) {
        const roomKey = `room:${id}`;
        const exists = await redisClient.exists(roomKey);
        if (!exists) {
          // cleanup stale reference
          await redisClient.sRem("rooms", id);
          continue;
        }
        const r = await redisClient.hGetAll(roomKey);
        const participants = await redisClient.sCard(`room:${id}:participants`);
        const createdAt = parseInt(r.createdAt || "0", 10);
        const ttlSeconds = parseInt(r.ttlSeconds || "0", 10);
        const age = Math.floor((Date.now() - createdAt) / 1000);
        const expiresIn = Math.max(0, ttlSeconds - age);
        out.push({
          id,
          ownerId: r.ownerId || null,
          participants,
          expiresIn,
          metadata: r.metadata ? JSON.parse(r.metadata) : {}
        });
      }
      res.json({ ok: true, rooms: out });
    } catch (err) {
      console.error("list rooms err", err);
      res.status(500).json({ ok: false, error: "server error" });
    }
  });

  // REST: get room details
  app.get("/rooms/:roomId", async (req, res) => {
    try {
      const { roomId } = req.params;
      const roomKey = `room:${roomId}`;
      const exists = await redisClient.exists(roomKey);
      if (!exists) return res.status(404).json({ ok: false, error: "Room not found" });
      const r = await redisClient.hGetAll(roomKey);
      const participants = await redisClient.sMembers(`room:${roomId}:participants`);
      res.json({
        ok: true,
        room: {
          id: roomId,
          ownerId: r.ownerId || null,
          participants,
          metadata: r.metadata ? JSON.parse(r.metadata) : {}
        }
      });
    } catch (err) {
      console.error("room detail err", err);
      res.status(500).json({ ok: false, error: "server error" });
    }
  });

  // REST: create invite (short-lived token + link)
  app.post("/rooms/:roomId/invite", async (req, res) => {
    try {
      const { roomId } = req.params;
      const { inviterId = "system", inviteeId = null, role = "participant", ttlSeconds = 900 } = req.body || {};
      const roomKey = `room:${roomId}`;
      const exists = await redisClient.exists(roomKey);
      if (!exists) return res.status(404).json({ ok: false, error: "Room not found" });

      const j = await signToken({ roomId, userId: inviteeId || `user_${Math.random().toString(36).slice(2,8)}`, role, expiresIn: ttlSeconds });
      const inviteLink = `${BASE_URL}/join?roomId=${roomId}&token=${j.token}`;
      res.json({ ok: true, invite: { token: j.token, jti: j.jti, inviteLink, roomId, ttlSeconds, role } });
    } catch (err) {
      console.error("create invite err", err);
      res.status(500).json({ ok: false, error: "server error" });
    }
  });

  // REST: explicit token generation
  app.post("/token", async (req, res) => {
    try {
      const { roomId, userId, role = "participant", ttlSeconds } = req.body || {};
      if (!roomId || !userId) return res.status(400).json({ ok: false, error: "roomId and userId required" });
      const roomKey = `room:${roomId}`;
      const exists = await redisClient.exists(roomKey);
      if (!exists) return res.status(404).json({ ok: false, error: "Room not found" });
      const expires = ttlSeconds || TOKEN_TTL;
      const j = await signToken({ roomId, userId, role, expiresIn: expires });
      res.json({ ok: true, token: j.token, jti: j.jti, expiresIn: expires });
    } catch (err) {
      console.error("token create err", err);
      res.status(500).json({ ok: false, error: "server error" });
    }
  });

  // REST: revoke token (delete token:{jti})
  app.post("/token/:jti/revoke", async (req, res) => {
    try {
      const { jti } = req.params;
      const key = `token:${jti}`;
      const exists = await redisClient.exists(key);
      if (!exists) return res.status(404).json({ ok: false, error: "Token not found" });
      await redisClient.del(key);
      res.json({ ok: true, revoked: jti });
    } catch (err) {
      console.error("revoke err", err);
      res.status(500).json({ ok: false, error: "server error" });
    }
  });

  // REST: check token status
  app.get("/token/:jti", async (req, res) => {
    try {
      const { jti } = req.params;
      const data = await redisClient.get(`token:${jti}`);
      if (!data) return res.json({ ok: true, found: false });
      res.json({ ok: true, found: true, token: JSON.parse(data) });
    } catch (err) {
      console.error("token get err", err);
      res.status(500).json({ ok: false, error: "server error" });
    }
  });

  // REST: delete / close room early (owner or admin should call)
  app.delete("/rooms/:roomId", async (req, res) => {
    try {
      const { roomId } = req.params;
      const roomKey = `room:${roomId}`;
      const exists = await redisClient.exists(roomKey);
      if (!exists) return res.status(404).json({ ok: false, error: "Room not found" });
      // delete keys
      await redisClient.del(roomKey);
      await redisClient.del(`room:${roomId}:participants`);
      await redisClient.sRem("rooms", roomId);
      // notify via socket.io (will need adapter)
      io.to(roomId).emit("room-closed", { roomId, reason: "closed_by_api" });
      // force sockets to leave is tricky; they will get the event and disconnect on client
      res.json({ ok: true, roomId });
    } catch (err) {
      console.error("delete room err", err);
      res.status(500).json({ ok: false, error: "server error" });
    }
  });

  /* --------------------------------------------------------
     Socket.IO initialization + Redis adapter + auth middleware
     -------------------------------------------------------- */

  const server = http.createServer(app);
  const io = new Server(server, { cors: { origin: "*" }, maxHttpBufferSize: 1e6 });

  // attach adapter using pub/sub clients
  io.adapter(createAdapter(pubClient, subClient));

  // Socket.IO auth middleware: accept token in handshake.auth.token or query token
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth?.token || socket.handshake.query?.token;
      if (!token) return next(new Error("Authentication token missing"));
      // verify token signature & presence in redis
      const payload = jwt.verify(token, JWT_SECRET);
      if (!payload?.jti) return next(new Error("Invalid token payload"));
      // confirm token still stored in redis
      const key = `token:${payload.jti}`;
      const stored = await redisClient.get(key);
      if (!stored) return next(new Error("Token not found / revoked / expired"));

      // attach auth info to socket
      socket.user = { id: payload.userId, role: payload.role, roomId: payload.roomId, jti: payload.jti };
      return next();
    } catch (err) {
      console.error("socket auth err", err.message || err);
      return next(new Error("Authentication error"));
    }
  });

  io.on("connection", async (socket) => {
    try {
      const { id: socketId } = socket;
      const { id: userId, role, roomId, jti } = { id: socket.user.id, role: socket.user.role, roomId: socket.user.roomId, jti: socket.user.jti };

      console.log(`Socket ${socketId} connected user ${userId} role ${role} room ${roomId}`);

      // Join socket.io room
      await socket.join(roomId);
      // Add to participants set in Redis (keep TTL aligned)
      const participantsKey = `room:${roomId}:participants`;
      await redisClient.sAdd(participantsKey, userId);

      // Optionally refresh TTLs for room and participants to keep alive while active
      const roomKey = `room:${roomId}`;
      const ttl = await redisClient.ttl(roomKey);
      if (ttl > 0) {
        // extend participant set TTL similarly
        await redisClient.expire(participantsKey, ttl);
      }

      // notify others in room
      socket.to(roomId).emit("user-joined", { socketId, userId, role });

      // signaling events
      socket.on("offer", (data) => {
        socket.to(roomId).emit("offer", { fromSocketId: socketId, fromUserId: userId, ...data });
      });

      socket.on("answer", (data) => {
        socket.to(roomId).emit("answer", { fromSocketId: socketId, fromUserId: userId, ...data });
      });

      socket.on("ice-candidate", (data) => {
        socket.to(roomId).emit("ice-candidate", { fromSocketId: socketId, fromUserId: userId, ...data });
      });

      socket.on("leave", async () => {
        await socket.leave(roomId);
        await redisClient.sRem(participantsKey, userId);
        socket.to(roomId).emit("user-left", { socketId, userId });
      });

      socket.on("disconnect", async (reason) => {
        console.log(`Socket ${socketId} disconnected: ${reason}`);
        await redisClient.sRem(participantsKey, userId);
        socket.to(roomId).emit("user-left", { socketId, userId });
      });
    } catch (err) {
      console.error("connection handler err", err);
    }
  });

  /* ---------------------------
     Simple admin UI served statically
     --------------------------- */

  app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, '../public/admin.html'));
  });

  /* ---------------------------
     Room expiry watcher to cleanup rooms set and emit room-closed
     --------------------------- */
  setInterval(async () => {
    try {
      const roomIds = await redisClient.sMembers("rooms");
      for (const id of roomIds) {
        const roomKey = `room:${id}`;
        const exists = await redisClient.exists(roomKey);
        if (!exists) {
          // cleanup
          await redisClient.sRem("rooms", id);
          // notify via socket.io
          io.to(id).emit("room-closed", { roomId: id, reason: "expired" });
        }
      }
    } catch (err) {
      console.error("expiry watcher err", err);
    }
  }, 30_000);

  server.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`);
    if (TURN_SERVER_URL) console.log(`TURN server (configured): ${TURN_SERVER_URL}`);
  });
} // end start

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
