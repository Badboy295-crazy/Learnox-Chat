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

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'uploads', 'avatars');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox';
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Error:', err));

// --- SCHEMAS ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    bio: { type: String, default: 'Hey there! I am using Learnox.' },
    avatar: { type: String, default: '' },
    status: { type: String, default: 'offline' },
    socketId: { type: String }, // To track connection for status
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
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
    chat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    edited: { type: Boolean, default: false },
    deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Message = mongoose.model('Message', MessageSchema);

// File Upload Config
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, `avatar-${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// Auth Middleware
const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error();
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) throw new Error();
        req.user = user;
        next();
    } catch (e) { res.status(401).json({ error: 'Please authenticate' }); }
};

// --- ROUTES ---

// Register
app.post('/api/register', async (req, res) => {
    try {
        let { name, username, email, password } = req.body;
        
        // Auto-add @ if missing
        if (username && !username.startsWith('@')) username = '@' + username;

        // Validation
        if (!name || !username || !email || !password) return res.status(400).json({ error: 'All fields required' });

        // Check duplicates
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) return res.status(400).json({ error: 'Email or Username already taken' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, username, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.json({ token, user });
    } catch (e) { 
        console.error(e);
        res.status(500).json({ error: 'Registration failed' }); 
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.json({ token, user });
    } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

// Update Profile
app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, bio, newPassword } = req.body;
        
        if (name) req.user.name = name;
        if (bio) req.user.bio = bio;
        if (newPassword && newPassword.trim() !== "") {
            req.user.password = await bcrypt.hash(newPassword, 10);
        }
        if (req.file) {
            req.user.avatar = `/uploads/avatars/${req.file.filename}`;
        }
        
        await req.user.save();
        res.json({ user: req.user });
    } catch (e) { res.status(500).json({ error: 'Update failed' }); }
});

// Search User (For 'Find' Tab)
app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        let query = req.query.q || '';
        if (!query) return res.json([]);
        if (!query.startsWith('@')) query = '@' + query;

        // Exact match for username
        const users = await User.find({ 
            username: query, 
            _id: { $ne: req.user._id } // Exclude self
        }).select('name username email avatar bio');
        
        res.json(users);
    } catch (e) { res.status(500).json({ error: 'Search failed' }); }
});

// Get Friends List
app.get('/api/friends', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({
            $or: [{ sender: req.user._id, status: 'accepted' }, { receiver: req.user._id, status: 'accepted' }]
        }).populate('sender receiver', 'name username avatar bio status');

        const friends = requests.map(r => r.sender._id.equals(req.user._id) ? r.receiver : r.sender);
        res.json(friends);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// Friend Requests
app.post('/api/friend-requests/send', authenticate, async (req, res) => {
    try {
        const { receiverId } = req.body;
        if (receiverId === req.user._id.toString()) return res.status(400).json({ error: 'Cannot add yourself' });

        const existing = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: receiverId },
                { sender: receiverId, receiver: req.user._id }
            ]
        });
        
        if (existing) {
            if (existing.status === 'accepted') return res.status(400).json({ error: 'Already friends' });
            return res.status(400).json({ error: 'Request already pending' });
        }

        const reqs = new FriendRequest({ sender: req.user._id, receiver: receiverId });
        await reqs.save();
        
        res.json({ message: 'Sent' });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/friend-requests/received', authenticate, async (req, res) => {
    try {
        const reqs = await FriendRequest.find({ 
            receiver: req.user._id, 
            status: 'pending' 
        }).populate('sender', 'name username avatar');
        res.json(reqs);
    } catch (e) { res.status(500).json({ error: 'Failed to fetch requests' }); }
});

app.post('/api/friend-requests/:id/accept', authenticate, async (req, res) => {
    try {
        const r = await FriendRequest.findById(req.params.id);
        if (!r) return res.status(404).json({ error: 'Request not found' });
        
        if (r.receiver.equals(req.user._id)) {
            r.status = 'accepted';
            await r.save();
            res.json({ message: 'Accepted' });
        } else {
            res.status(403).json({ error: 'Unauthorized' });
        }
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/friend-requests/:id/reject', authenticate, async (req, res) => {
    try {
        const r = await FriendRequest.findById(req.params.id);
        if (r && r.receiver.equals(req.user._id)) {
            await r.deleteOne();
            res.json({ message: 'Rejected' });
        } else {
            res.status(400).json({ error: 'Error' });
        }
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// Chats
app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({ participants: req.user._id })
            .populate('participants', 'name username avatar status bio')
            .populate('lastMessage')
            .sort({ updatedAt: -1 });
        res.json(chats);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/chats', authenticate, async (req, res) => {
    try {
        const { userId } = req.body;
        let chat = await Chat.findOne({ participants: { $all: [req.user._id, userId] } });
        if (!chat) {
            chat = new Chat({ participants: [req.user._id, userId] });
            await chat.save();
        }
        await chat.populate('participants', 'name username avatar status');
        res.json(chat);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/chats/:chatId/messages', authenticate, async (req, res) => {
    try {
        const msgs = await Message.find({ chat: req.params.chatId, deletedFor: { $ne: req.user._id } })
            .populate('sender', 'name')
            .sort({ createdAt: 1 });
        res.json(msgs);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text } = req.body;
        const msg = new Message({ chat: chatId, sender: req.user._id, text });
        await msg.save();
        
        await Chat.findByIdAndUpdate(chatId, { lastMessage: msg._id, updatedAt: Date.now() });
        
        const popMsg = await msg.populate('sender', 'name');
        io.to(chatId).emit('new_message', popMsg);
        res.json(popMsg);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// Fallback for frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// --- SOCKET.IO ---
const userSockets = new Map(); // Map<UserId, SocketId>

io.on('connection', (socket) => {
    socket.on('join_user', async (userId) => {
        socket.join(userId);
        userSockets.set(userId, socket.id);
        userSockets.set(socket.id, userId); // Reverse mapping for disconnect

        await User.findByIdAndUpdate(userId, { status: 'online' });
        socket.broadcast.emit('user_status_changed', { userId, status: 'online' });
    });

    socket.on('join_chat', (chatId) => socket.join(chatId));
    
    socket.on('typing', (data) => socket.to(data.chatId).emit('typing', data));
    socket.on('stop_typing', (data) => socket.to(data.chatId).emit('stop_typing', data));

    socket.on('disconnect', async () => {
        const userId = userSockets.get(socket.id);
        if (userId) {
            await User.findByIdAndUpdate(userId, { status: 'offline' });
            socket.broadcast.emit('user_status_changed', { userId, status: 'offline' });
            userSockets.delete(userId);
            userSockets.delete(socket.id);
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));