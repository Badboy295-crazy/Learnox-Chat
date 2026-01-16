import express from "express";
import http from "http";
import path from "path";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import { Server } from "socket.io";

import User from "./models/User.js";
import Chat from "./models/Chat.js";
import Message from "./models/Message.js";
import FriendRequest from "./models/FriendRequest.js";
import auth from "./middleware/auth.js";

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const __dirnameFull = path.resolve();

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ? Cache fix (VERY IMPORTANT)
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.use("/uploads", express.static("uploads"));
app.use(express.static(path.join(__dirnameFull, "public")));

// ===== DATABASE =====
mongoose.connect(process.env.MONGO_URI);

// ===== MULTER =====
const storage = multer.diskStorage({
  destination: "uploads/avatars",
  filename: (_, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});
const upload = multer({ storage });

// ===== SOCKET AUTH =====
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.userId;
    await User.findByIdAndUpdate(socket.userId, { status: "online" });
    next();
  } catch {
    next(new Error("Authentication error"));
  }
});

io.on("connection", socket => {
  socket.join(socket.userId.toString());

  socket.on("typing", data => {
    socket.to(data.chatId).emit("typing", {
      chatId: data.chatId,
      userId: socket.userId,
      userName: data.userName
    });
  });

  socket.on("typing_stopped", data => {
    socket.to(data.chatId).emit("typing_stopped", data);
  });

  socket.on("disconnect", async () => {
    await User.findByIdAndUpdate(socket.userId, {
      status: "offline",
      lastSeen: new Date()
    });
  });
});

// ================= AUTH =================
app.post("/api/register", async (req, res) => {
  const { username, name, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: "Missing fields" });

  const exists = await User.findOne({
    $or: [{ username }, { email }]
  });
  if (exists) return res.status(400).json({ error: "User exists" });

  const user = await User.create({
    username,
    name,
    email,
    password: await bcrypt.hash(password, 10)
  });

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });

  res.json({ token, user });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({
    $or: [{ username }, { email: username }]
  });

  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });

  res.json({ token, user });
});

// ================= PROFILE =================
app.put("/api/profile", auth, upload.single("avatar"), async (req, res) => {
  if (req.body.name) req.user.name = req.body.name;
  if (req.file) req.user.avatar = `/uploads/avatars/${req.file.filename}`;

  if (req.body.currentPassword && req.body.newPassword) {
    const ok = await bcrypt.compare(req.body.currentPassword, req.user.password);
    if (!ok) return res.status(400).json({ error: "Wrong password" });
    req.user.password = await bcrypt.hash(req.body.newPassword, 10);
  }

  await req.user.save();
  const u = req.user.toObject();
  delete u.password;
  res.json({ user: u });
});

// ================= FRIENDS =================
app.get("/api/friends", auth, async (req, res) => {
  const user = await User.findById(req.user._id).populate("friends");
  res.json(user.friends);
});

app.post("/api/friend-requests/:id", auth, async (req, res) => {
  await FriendRequest.create({
    sender: req.user._id,
    receiver: req.params.id
  });
  res.json({ success: true });
});

app.get("/api/friend-requests/received", auth, async (req, res) => {
  const reqs = await FriendRequest.find({ receiver: req.user._id }).populate(
    "sender"
  );
  res.json(reqs);
});

app.post("/api/friend-requests/:id/accept", auth, async (req, res) => {
  const fr = await FriendRequest.findById(req.params.id);
  const sender = await User.findById(fr.sender);
  sender.friends.push(req.user._id);
  req.user.friends.push(sender._id);
  await sender.save();
  await req.user.save();
  await fr.deleteOne();
  res.json({ success: true });
});

// ================= CHATS =================
app.get("/api/chats", auth, async (req, res) => {
  const chats = await Chat.find({ participants: req.user._id })
    .populate("participants", "username name avatar status");

  const data = chats.map(c => ({
    _id: c._id,
    otherParticipant: c.participants.find(
      p => p._id.toString() !== req.user._id.toString()
    ),
    unreadCount: c.unreadCount?.get(req.user._id.toString()) || 0
  }));

  res.json(data);
});

// ================= MESSAGES =================
app.post("/api/messages", auth, async (req, res) => {
  const msg = await Message.create({
    chatId: req.body.chatId,
    sender: req.user._id,
    text: req.body.text,
    status: "sent"
  });

  io.to(req.body.chatId).emit("new_message", {
    chatId: req.body.chatId,
    message: msg
  });

  res.json(msg);
});

// ================= DELETE ACCOUNT =================
app.delete("/api/account/delete", auth, async (req, res) => {
  const ok = await bcrypt.compare(req.body.password, req.user.password);
  if (!ok) return res.status(400).json({ error: "Wrong password" });

  await User.findByIdAndDelete(req.user._id);
  await Chat.deleteMany({ participants: req.user._id });
  await Message.deleteMany({ sender: req.user._id });

  res.json({ success: true });
});

// ===== SPA FALLBACK =====
app.get("*", (_, res) => {
  res.sendFile(path.join(__dirnameFull, "public", "index.html"));
});

server.listen(process.env.PORT || 3000, () =>
  console.log("? Server running")
);
