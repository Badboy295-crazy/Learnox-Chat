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
const io = socketIo(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

const uploadDir = path.join(__dirname, 'uploads', 'avatars');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/learnox');

// --- SCHEMAS ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    bio: { type: String, default: 'Hey there!' },
    avatar: { type: String, default: '' },
    status: { type: String, default: 'offline' },
    lastSeen: { type: Date, default: Date.now }
});

const FriendRequestSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['pending', 'accepted'], default: 'pending' }
});

const ChatSchema = new mongoose.Schema({
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
    updatedAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
    chat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat' },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: { type: String, required: true },
    status: { type: String, enum: ['sent', 'delivered', 'seen'], default: 'sent' },
    edited: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Message = mongoose.model('Message', MessageSchema);

// --- MIDDLEWARES ---
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = await User.findById(decoded.userId);
        if (!req.user) throw new Error();
        next();
    } catch (e) { res.status(401).json({ error: 'Unauthorized' }); }
};

// Privacy Check: Kya user is chat ka hissa hai?
const authorizeChat = async (req, res, next) => {
    const chat = await Chat.findById(req.params.chatId || req.body.chatId);
    if (!chat || !chat.participants.includes(req.user._id)) {
        return res.status(403).json({ error: 'Access Denied: Not your chat' });
    }
    next();
};

// --- API ROUTES ---

app.post('/api/register', async (req, res) => {
    try {
        let { name, username, email, password } = req.body;
        if (!username.startsWith('@')) username = '@' + username;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, username, email, password: hashedPassword });
        await user.save();
        res.json({ token: jwt.sign({ userId: user._id }, JWT_SECRET), user });
    } catch (e) { res.status(400).json({ error: 'User already exists' }); }
});

app.post('/api/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        res.json({ token: jwt.sign({ userId: user._id }, JWT_SECRET), user });
    } else { res.status(401).json({ error: 'Invalid Credentials' }); }
});

// Profile Update (Name, Bio, Password, Avatar)
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, `avatar-${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    if (req.body.name) req.user.name = req.body.name;
    if (req.body.bio) req.user.bio = req.body.bio;
    if (req.body.password) req.user.password = await bcrypt.hash(req.body.password, 10);
    if (req.file) req.user.avatar = `/uploads/avatars/${req.file.filename}`;
    await req.user.save();
    res.json(req.user);
});

// Chat Data Privacy: Only return chats where user is participant
app.get('/api/chats', authenticate, async (req, res) => {
    const chats = await Chat.find({ participants: req.user._id })
        .populate('participants', 'name username avatar status')
        .populate('lastMessage')
        .sort({ updatedAt: -1 });
    res.json(chats);
});

app.get('/api/chats/:chatId/messages', authenticate, authorizeChat, async (req, res) => {
    const messages = await Message.find({ chat: req.params.chatId }).sort({ createdAt: 1 });
    // Mark as seen
    await Message.updateMany(
        { chat: req.params.chatId, sender: { $ne: req.user._id }, status: { $ne: 'seen' } },
        { status: 'seen' }
    );
    io.to(req.params.chatId).emit('messages_seen', { chatId: req.params.chatId });
    res.json(messages);
});

app.post('/api/messages', authenticate, authorizeChat, async (req, res) => {
    const msg = new Message({ ...req.body, sender: req.user._id });
    await msg.save();
    await Chat.findByIdAndUpdate(req.body.chatId, { lastMessage: msg._id, updatedAt: Date.now() });
    io.to(req.body.chatId).emit('new_message', msg);
    res.json(msg);
});

app.delete('/api/messages/:id', authenticate, async (req, res) => {
    const msg = await Message.findById(req.params.id);
    if (msg.sender.equals(req.user._id)) {
        await msg.deleteOne();
        io.to(msg.chat.toString()).emit('message_deleted', req.params.id);
        res.json({ success: true });
    }
});

app.put('/api/messages/:id', authenticate, async (req, res) => {
    const msg = await Message.findById(req.params.id);
    if (msg.sender.equals(req.user._id)) {
        msg.text = req.body.text;
        msg.edited = true;
        await msg.save();
        io.to(msg.chat.toString()).emit('message_updated', msg);
        res.json(msg);
    }
});

// Friends & Search
app.get('/api/users/search', authenticate, async (req, res) => {
    const users = await User.find({ username: req.query.q }).select('name username avatar');
    res.json(users);
});

app.delete('/api/friends/:id', authenticate, async (req, res) => {
    await FriendRequest.findOneAndDelete({
        $or: [
            { sender: req.user._id, receiver: req.params.id },
            { sender: req.params.id, receiver: req.user._id }
        ]
    });
    res.json({ success: true });
});

// Socket Logic
const userSockets = new Map();
io.on('connection', (socket) => {
    socket.on('join', (userId) => {
        userSockets.set(userId, socket.id);
        socket.join(userId);
    });
    socket.on('join_chat', (chatId) => socket.join(chatId));
    socket.on('typing', (data) => socket.to(data.chatId).emit('user_typing', data));
});

server.listen(3000, () => console.log('Server running on 3000'));