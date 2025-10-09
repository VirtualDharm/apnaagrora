import express from "express";
import http from "http";
import { Server } from "socket.io";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

// Resolve dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Serve all files in /public
app.use(express.static(path.join(__dirname, "../public")));

// Explicit aliases
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/admin.html"));
});

app.get("/test-client", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/test-client.html"));
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const TOKEN_TTL = parseInt(process.env.TOKEN_TTL_SECONDS || "3600", 10);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const TURN_SERVER_URL = process.env.TURN_SERVER_URL || "";
const TURN_USERNAME = process.env.TURN_USERNAME || "";
const TURN_PASSWORD = process.env.TURN_PASSWORD || "";

// In-memory stores
const rooms = new Map(); // roomId -> {ownerId, participants:Map, createdAt, ttlSeconds, metadata}
const tokens = new Map(); // jti -> {roomId, userId, role, expiresAt}
console.log("Server started with memory store. Data resets on restart.");

/* -------------------------
   Utility functions
-------------------------- */
function makeRoomId(len = 7) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function signToken({ roomId, userId, role = "participant", expiresIn = TOKEN_TTL }) {
  const jti = uuidv4();
  const payload = { roomId, userId, role, jti };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn });
  const expiresAt = Date.now() + expiresIn * 1000;
  tokens.set(jti, { roomId, userId, role, expiresAt });
  return { token, jti, expiresAt };
}

function verifyAndCheckToken(token) {
  const payload = jwt.verify(token, JWT_SECRET);
  const stored = tokens.get(payload.jti);
  if (!stored) throw new Error("Token revoked or expired");
  return payload;
}

/* -------------------------
   REST API
-------------------------- */

// Health check
app.get("/", (req, res) => res.send("Casting API running in memory mode ✅"));

// Create room
app.post("/rooms", (req, res) => {
  const { ownerId, ttlSeconds = 3600, metadata = {} } = req.body || {};
  const roomId = makeRoomId();
  const room = { ownerId, participants: new Map(), createdAt: Date.now(), ttlSeconds, metadata };
  rooms.set(roomId, room);
  res.json({ ok: true, room: { id: roomId, ...room, participants: [] } });
});

// List rooms (with participants)
app.get("/rooms", (req, res) => {
  const list = Array.from(rooms.entries()).map(([id, r]) => ({
    id,
    ownerId: r.ownerId,
    participants: Array.from((r.participants?.values() || [])),
    ttlSeconds: r.ttlSeconds,
    metadata: r.metadata,
    createdAt: r.createdAt
  }));
  res.json({ ok: true, rooms: list });
});

// Get single room details
app.get("/rooms/:roomId", (req, res) => {
  const room = rooms.get(req.params.roomId);
  if (!room) return res.status(404).json({ ok: false, error: "Room not found" });
  res.json({
    ok: true,
    room: {
      id: req.params.roomId,
      ownerId: room.ownerId,
      participants: Array.from(room.participants?.values() || []),
      createdAt: room.createdAt,
      ttlSeconds: room.ttlSeconds,
      metadata: room.metadata
    }
  });
});

// Create invite
app.post("/rooms/:roomId/invite", (req, res) => {
  const room = rooms.get(req.params.roomId);
  if (!room) return res.status(404).json({ ok: false, error: "Room not found" });

  const inviteeId = req.body?.inviteeId?.trim() || "guest_" + Math.random().toString(36).slice(2, 8);
  const ttlSeconds = parseInt(req.body?.ttlSeconds || 900, 10);
  const role = req.body?.role || "participant";

  const { token, jti, expiresAt } = signToken({
    roomId: req.params.roomId,
    userId: inviteeId,
    role,
    expiresIn: ttlSeconds,
  });

  const inviteLink = `${BASE_URL}/join?roomId=${req.params.roomId}&token=${token}`;
  res.json({ ok: true, invite: { roomId: req.params.roomId, token, jti, expiresAt, inviteLink } });
});

// Generate token manually
app.post("/token", (req, res) => {
  const { roomId, role = "participant", ttlSeconds } = req.body || {};
  if (!rooms.has(roomId)) return res.status(404).json({ ok: false, error: "Room not found" });

  const userId = req.body?.userId?.trim() || "user_" + Math.random().toString(36).slice(2, 8);
  const { token, jti, expiresAt } = signToken({ roomId, userId, role, expiresIn: ttlSeconds || TOKEN_TTL });

  res.json({ ok: true, token, jti, expiresAt });
});

// Revoke token
app.post("/token/:jti/revoke", (req, res) => {
  const { jti } = req.params;
  if (!tokens.has(jti)) return res.status(404).json({ ok: false, error: "Token not found" });
  tokens.delete(jti);
  res.json({ ok: true, revoked: jti });
});

// Check token status
app.get("/token/:jti", (req, res) => {
  const data = tokens.get(req.params.jti);
  if (!data) return res.json({ ok: true, found: false });
  res.json({ ok: true, found: true, token: data });
});

// Delete room
app.delete("/rooms/:roomId", (req, res) => {
  const { roomId } = req.params;
  if (!rooms.has(roomId)) return res.status(404).json({ ok: false, error: "Room not found" });
  rooms.delete(roomId);
  io.to(roomId).emit("room-closed", { roomId, reason: "closed_by_api" });
  res.json({ ok: true, roomId });
});

/* -------------------------
   SOCKET.IO + AUTH
-------------------------- */

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;
    if (!token) return next(new Error("No token provided"));
    const payload = verifyAndCheckToken(token);
    socket.user = {
      id: payload.userId || "anon_" + socket.id.slice(0, 6),
      roomId: payload.roomId,
      role: payload.role,
      jti: payload.jti
    };
    next();
  } catch (err) {
    console.error("Socket auth error:", err.message);
    next(new Error("Unauthorized"));
  }
});

io.on("connection", (socket) => {
  const { id: socketId } = socket;
  const { id: userId, roomId, role } = socket.user;

  console.log(`User ${userId} joined room ${roomId}`);

  if (!rooms.has(roomId)) {
    rooms.set(roomId, { ownerId: null, participants: new Map(), createdAt: Date.now(), ttlSeconds: 3600, metadata: {} });
  }

  const room = rooms.get(roomId);
  if (!room.participants) room.participants = new Map();

  // Save participant details
  room.participants.set(userId, {
    userId,
    role,
    socketId,
    joinedAt: new Date().toISOString()
  });

  socket.join(roomId);
  socket.to(roomId).emit("user-joined", { socketId, userId, role });

  socket.on("offer", (data) => socket.to(roomId).emit("offer", { from: userId, sdp: data.sdp }));
  socket.on("answer", (data) => socket.to(roomId).emit("answer", { from: userId, sdp: data.sdp }));
  socket.on("ice-candidate", (data) => socket.to(roomId).emit("ice-candidate", { from: userId, candidate: data.candidate }));

  socket.on("disconnect", () => {
    console.log(`User ${userId} left ${roomId}`);
    if (room.participants) room.participants.delete(userId);
    socket.to(roomId).emit("user-left", { userId });
  });
});

/* -------------------------
   Cleanup
-------------------------- */
setInterval(() => {
  const now = Date.now();
  for (const [jti, data] of tokens.entries()) {
    if (data.expiresAt <= now) tokens.delete(jti);
  }
  for (const [id, r] of rooms.entries()) {
    if (Date.now() - r.createdAt > r.ttlSeconds * 1000) {
      rooms.delete(id);
      io.to(id).emit("room-closed", { roomId: id, reason: "expired" });
    }
  }
}, 15 * 1000);

/* -------------------------
   Start server
-------------------------- */
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  if (TURN_SERVER_URL) console.log(`TURN: ${TURN_SERVER_URL}`);
});
