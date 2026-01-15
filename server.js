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
    cors: { origin: "*", methods: ["GET", "POST"] }
});

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox';
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error(err));

// --- MODELS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true }, // NEW: Unique ID
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
    updatedAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
    chat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    status: { type: String, enum: ['sent', 'delivered', 'seen'], default: 'sent' }, // Ticks logic
    edited: { type: Boolean, default: false },
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
const userSockets = new Map(); // userId -> socketId

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
    console.log(`User connected: ${socket.userId}`);
    userSockets.set(socket.userId, socket.id);
    socket.join(socket.userId); // Join personal room

    // 1. Set User Online
    await User.findByIdAndUpdate(socket.userId, { status: 'online' });
    io.emit('user_status', { userId: socket.userId, status: 'online' });

    // 2. Deliver Pending Messages (Grey Tick -> Double Grey Tick)
    // Find messages sent TO this user that are 'sent' and mark 'delivered'
    const pendingMsgs = await Message.find({ 
        sender: { $ne: socket.userId }, 
        status: 'sent',
        // We need to find chats where this user is a participant. 
        // For simplicity, we assume if you are socket.userId, you receive messages in your chats.
    }).populate('chat');

    // Efficiently update status
    for (let msg of pendingMsgs) {
        if (msg.chat.participants.includes(socket.userId)) {
            msg.status = 'delivered';
            await msg.save();
            // Notify the SENDER that message is delivered
            const senderSocket = userSockets.get(msg.sender.toString());
            if (senderSocket) io.to(senderSocket).emit('msg_status_update', { msgId: msg._id, status: 'delivered', chatId: msg.chat._id });
        }
    }

    // Join Chat Room
    socket.on('join_chat', async (chatId) => {
        socket.join(chatId);
        // Mark messages in this chat as SEEN (Double Blue Tick)
        await Message.updateMany(
            { chat: chatId, sender: { $ne: socket.userId }, status: { $ne: 'seen' } },
            { status: 'seen' }
        );
        // Notify other participants in this chat
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

// 1. Auth & Profile
app.post('/api/register', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;
        if (await User.findOne({ $or: [{ email }, { username }] })) return res.status(400).json({ error: 'Email or Username already taken' });
        const user = new User({ username, name, email, password: await bcrypt.hash(password, 10) });
        await user.save();
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user });
    } catch (e) { res.status(500).json({ error: 'Register failed' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user });
    } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, currentPassword, newPassword } = req.body;
        const user = req.user;
        if (currentPassword && !(await bcrypt.compare(currentPassword, user.password))) return res.status(401).json({ error: 'Wrong password' });
        if (name) user.name = name;
        if (newPassword) user.password = await bcrypt.hash(newPassword, 10);
        if (req.file) user.avatar = `/uploads/avatars/${req.file.filename}`;
        await user.save();
        res.json({ user });
    } catch (e) { res.status(500).json({ error: 'Update failed' }); }
});

// 2. Friends & Users
app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        const q = req.query.q || '';
        if (q.length < 2) return res.json([]);
        
        // Find users matching username/email
        const users = await User.find({
            _id: { $ne: req.user._id },
            username: { $regex: q, $options: 'i' }
        }).select('name username avatar');

        // Check friendship status for each result
        const results = await Promise.all(users.map(async (u) => {
            const reqStatus = await FriendRequest.findOne({
                $or: [
                    { sender: req.user._id, receiver: u._id },
                    { sender: u._id, receiver: req.user._id }
                ]
            });
            return { ...u.toObject(), requestStatus: reqStatus ? reqStatus.status : 'none', requestId: reqStatus?._id };
        }));

        res.json(results);
    } catch (e) { res.status(500).json({ error: 'Search failed' }); }
});

app.post('/api/friend-request', authenticate, async (req, res) => {
    try {
        const { receiverId } = req.body;
        const exists = await FriendRequest.findOne({ $or: [{ sender: req.user._id, receiver: receiverId }, { sender: receiverId, receiver: req.user._id }] });
        if (exists) return res.status(400).json({ error: 'Request already exists' });
        
        const newReq = await FriendRequest.create({ sender: req.user._id, receiver: receiverId });
        await newReq.populate('sender', 'name username avatar');
        
        const sock = userSockets.get(receiverId);
        if (sock) io.to(sock).emit('new_friend_request', newReq);
        
        res.json(newReq);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/friend-request/respond', authenticate, async (req, res) => {
    try {
        const { requestId, action } = req.body; // action: 'accepted' or 'rejected'
        const freq = await FriendRequest.findById(requestId);
        if (!freq) return res.status(404).json({ error: 'Not found' });
        
        freq.status = action;
        await freq.save();

        if (action === 'accepted') {
            const sock = userSockets.get(freq.sender.toString());
            if (sock) io.to(sock).emit('request_accepted', { friendName: req.user.name });
        }
        res.json(freq);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/friends', authenticate, async (req, res) => {
    try {
        const friends = await FriendRequest.find({
            $or: [{ sender: req.user._id }, { receiver: req.user._id }],
            status: 'accepted'
        }).populate('sender receiver', 'name username avatar status lastSeen');
        
        const list = friends.map(f => {
            const u = f.sender._id.equals(req.user._id) ? f.receiver : f.sender;
            return { _id: u._id, name: u.name, username: u.username, avatar: u.avatar, status: u.status, lastSeen: u.lastSeen };
        });
        res.json(list);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/block', authenticate, async (req, res) => {
    try {
        const { userId } = req.body;
        if (!req.user.blockedUsers.includes(userId)) {
            req.user.blockedUsers.push(userId);
            await req.user.save();
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

// 3. Chats
app.get('/api/chats', authenticate, async (req, res) => {
    try {
        let chats = await Chat.find({ participants: req.user._id })
            .populate('participants', 'name username avatar status lastSeen')
            .populate('lastMessage')
            .sort({ updatedAt: -1 });

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

app.delete('/api/chats/:chatId', authenticate, async (req, res) => {
    try {
        await Message.updateMany({ chat: req.params.chatId }, { $push: { deletedFor: req.user._id } });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/messages/:chatId', authenticate, async (req, res) => {
    try {
        const msgs = await Message.find({ chat: req.params.chatId, deletedFor: { $ne: req.user._id } })
            .sort({ createdAt: 1 });
        res.json(msgs);
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text, tempId } = req.body;
        const chat = await Chat.findById(chatId);
        
        // Block check
        const otherId = chat.participants.find(p => !p.equals(req.user._id));
        const otherUser = await User.findById(otherId);
        if (otherUser.blockedUsers.includes(req.user._id)) return res.status(403).json({ error: 'Blocked' });

        // Initial status: If user online -> delivered, else sent
        const initialStatus = otherUser.status === 'online' ? 'delivered' : 'sent';

        const msg = await Message.create({ chat: chatId, sender: req.user._id, text, status: initialStatus });
        chat.lastMessage = msg._id;
        chat.updatedAt = Date.now();
        await chat.save();

        const msgData = { ...msg.toObject(), tempId }; // Return tempId to client to replace
        
        // Broadcast to OTHERS (sender gets response via API)
        socket.to(chatId).emit('new_message', msgData);
        
        res.json(msgData);
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.put('/api/messages/:id', authenticate, async (req, res) => {
    try {
        const msg = await Message.findByIdAndUpdate(req.params.id, { text: req.body.text, edited: true }, { new: true });
        io.to(msg.chat.toString()).emit('message_updated', msg);
        res.json(msg);
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.delete('/api/messages/:id', authenticate, async (req, res) => {
    try {
        const msg = await Message.findById(req.params.id);
        if(msg.sender.toString() === req.user._id.toString()){
             // If I am sender, actually delete for everyone (or add flag)
             // Here we just hide it to simulate 'Delete for everyone'
             msg.deletedFor = [...msg.deletedFor, ...req.user.blockedUsers]; // Hacky way or add a 'isDeleted' flag
             await Message.deleteOne({ _id: req.params.id }); // Hard delete for simplicity requested
             io.to(msg.chat.toString()).emit('message_deleted', { _id: req.params.id, chatId: msg.chat });
        } else {
            msg.deletedFor.push(req.user._id); // Delete for me
            await msg.save();
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

// Search User by ID (For View Profile)
app.get('/api/user/:id', authenticate, async (req, res) => {
    try {
        const u = await User.findById(req.params.id).select('-password -blockedUsers');
        res.json(u);
    } catch (e) { res.status(404).json({ error: 'Not found' }); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
server.listen(process.env.PORT || 3000, () => console.log('Server Running'));