const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

const io = socketIo(server, {
    cors: { origin: "*", methods: ["GET", "POST", "PUT", "DELETE"] }
});

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox_final';
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error(err));

// --- MODELS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String },
    status: { type: String, default: 'offline' },
    lastSeen: { type: Date, default: Date.now },
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

const FriendRequestSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const ChatSchema = new mongoose.Schema({
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
    updatedAt: { type: Date, default: Date.now } // Crucial for sorting
});

const MessageSchema = new mongoose.Schema({
    chat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    status: { type: String, enum: ['sent', 'delivered', 'seen'], default: 'sent' },
    edited: { type: Boolean, default: false },
    reactions: [{ 
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        emoji: String
    }],
    deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Message = mongoose.model('Message', MessageSchema);

// File Upload
const uploadDir = 'uploads/avatars/';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, uploadDir),
        filename: (req, file, cb) => cb(null, `avatar-${Date.now()}${path.extname(file.originalname)}`)
    }),
    limits: { fileSize: 5 * 1024 * 1024 }
});

const JWT_SECRET = process.env.JWT_SECRET || 'learnox-secret';

// Auth Middleware
const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error();
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = await User.findById(decoded.userId).select('-password');
        if (!req.user) throw new Error();
        next();
    } catch (e) { res.status(401).json({ error: 'Auth failed' }); }
};

// --- SOCKET LOGIC ---
const userSockets = new Map();

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            socket.userId = decoded.userId;
            return next();
        } catch(e) {}
    }
    next(new Error('Auth error'));
});

io.on('connection', async (socket) => {
    userSockets.set(socket.userId, socket.id);
    socket.join(socket.userId);
    await User.findByIdAndUpdate(socket.userId, { status: 'online' });
    io.emit('user_status', { userId: socket.userId, status: 'online' });

    socket.on('join_chat', async (chatId) => {
        socket.join(chatId);
        // Mark messages seen
        await Message.updateMany(
            { chat: chatId, sender: { $ne: socket.userId }, status: { $ne: 'seen' } },
            { status: 'seen' }
        );
        socket.to(chatId).emit('msgs_seen', { chatId });
    });

    socket.on('typing_start', (data) => socket.to(data.chatId).emit('typing_start', { chatId: data.chatId, userId: socket.userId }));
    socket.on('typing_stop', (data) => socket.to(data.chatId).emit('typing_stop', { chatId: data.chatId, userId: socket.userId }));

    socket.on('disconnect', async () => {
        userSockets.delete(socket.userId);
        await User.findByIdAndUpdate(socket.userId, { status: 'offline', lastSeen: Date.now() });
        io.emit('user_status', { userId: socket.userId, status: 'offline', lastSeen: Date.now() });
    });
});

// --- API ROUTES ---

// Auth & Profile
app.post('/api/register', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;
        if (await User.findOne({ $or: [{ email }, { username }] })) return res.status(400).json({ error: 'Taken' });
        const user = new User({ username, name, email, password: await bcrypt.hash(password, 10) });
        await user.save();
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid' });
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const user = req.user;
        if (req.body.name) user.name = req.body.name;
        if (req.file) user.avatar = `/uploads/avatars/${req.file.filename}`;
        await user.save();
        res.json({ user });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

// Friends & Search
app.get('/api/users/search', authenticate, async (req, res) => {
    const q = req.query.q || '';
    if (q.length < 1) return res.json([]);
    const users = await User.find({ _id: { $ne: req.user._id }, username: { $regex: q, $options: 'i' } }).select('name username avatar');
    res.json(users);
});

app.post('/api/friend-request', authenticate, async (req, res) => {
    const { receiverId } = req.body;
    if(await FriendRequest.findOne({ $or: [{ sender: req.user._id, receiver: receiverId }, { sender: receiverId, receiver: req.user._id }] })) 
        return res.status(400).json({ error: 'Exists' });
    const r = await FriendRequest.create({ sender: req.user._id, receiver: receiverId });
    res.json(r);
});

// Chats
app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({ participants: req.user._id })
            .populate('participants', 'name username avatar status lastSeen')
            .populate('lastMessage')
            .sort({ updatedAt: -1 }); // Backend sorting

        const data = await Promise.all(chats.map(async c => {
            const unread = await Message.countDocuments({ chat: c._id, sender: { $ne: req.user._id }, status: { $ne: 'seen' } });
            return { ...c.toObject(), unreadCount: unread };
        }));
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/chats', authenticate, async (req, res) => {
    try {
        const { targetId } = req.body;
        let chat = await Chat.findOne({ participants: { $all: [req.user._id, targetId] } });
        if (!chat) chat = await Chat.create({ participants: [req.user._id, targetId] });
        await chat.populate('participants', 'name username avatar status');
        res.json(chat);
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

// Messages
app.get('/api/messages/:chatId', authenticate, async (req, res) => {
    const msgs = await Message.find({ chat: req.params.chatId, deletedFor: { $ne: req.user._id } }).sort({ createdAt: 1 });
    res.json(msgs);
});

app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text, tempId } = req.body;
        const chat = await Chat.findById(chatId);
        const otherId = chat.participants.find(p => !p.equals(req.user._id));
        const otherUser = await User.findById(otherId);
        
        if (otherUser.blockedUsers.includes(req.user._id)) return res.status(403).json({ error: 'Blocked' });

        const msg = await Message.create({ 
            chat: chatId, sender: req.user._id, text, 
            status: otherUser.status === 'online' ? 'delivered' : 'sent' 
        });

        // UPDATE CHAT TIMESTAMP for Sorting
        chat.lastMessage = msg._id;
        chat.updatedAt = Date.now();
        await chat.save();

        const msgData = { ...msg.toObject(), tempId };
        socket.to(chatId).emit('new_message', msgData);
        res.json(msgData);
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.put('/api/messages/:id', authenticate, async (req, res) => {
    const msg = await Message.findByIdAndUpdate(req.params.id, { text: req.body.text, edited: true }, { new: true });
    io.to(msg.chat.toString()).emit('message_updated', msg);
    res.json(msg);
});

app.delete('/api/messages/:id', authenticate, async (req, res) => {
    const msg = await Message.findById(req.params.id);
    if(msg.sender.toString() === req.user._id.toString()){
        await Message.deleteOne({ _id: req.params.id }); 
        io.to(msg.chat.toString()).emit('message_deleted', { _id: req.params.id, chatId: msg.chat });
    } else {
        msg.deletedFor.push(req.user._id);
        await msg.save();
    }
    res.json({ success: true });
});

// Reactions
app.post('/api/messages/:id/react', authenticate, async (req, res) => {
    try {
        const { emoji } = req.body;
        const msg = await Message.findById(req.params.id);
        
        // Remove existing reaction from this user if any
        msg.reactions = msg.reactions.filter(r => r.user.toString() !== req.user._id.toString());
        msg.reactions.push({ user: req.user._id, emoji });
        await msg.save();
        
        io.to(msg.chat.toString()).emit('message_reacted', { msgId: msg._id, reactions: msg.reactions, chatId: msg.chat });
        res.json(msg);
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/user/:id', authenticate, async (req, res) => {
    const u = await User.findById(req.params.id).select('-password');
    res.json(u);
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
server.listen(process.env.PORT || 3000, () => console.log('Server Running'));