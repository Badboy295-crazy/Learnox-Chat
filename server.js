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

// Serve Static Files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox';
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Error:', err));

// --- Schemas ---

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String, default: '/uploads/default-avatar.png' },
    status: { type: String, default: 'offline' },
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // New: Block List
    createdAt: { type: Date, default: Date.now }
});

const FriendRequestSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' }
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
    status: { type: String, enum: ['sent', 'delivered', 'seen'], default: 'sent' },
    edited: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Message = mongoose.model('Message', MessageSchema);

// --- Multer (Uploads) ---
const uploadDir = 'uploads/avatars/';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, `avatar-${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// --- Middleware ---
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

// --- Routes ---

// Auth
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (await User.findOne({ email })) return res.status(400).json({ error: 'Email exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.json({ token, user: { id: user._id, name, email, avatar: user.avatar } });
    } catch (e) { res.status(500).json({ error: 'Register failed' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.json({ token, user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar, blockedUsers: user.blockedUsers } });
    } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

// Profile Update (No Email Change)
app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, newPassword } = req.body; // Removed email from destructuring
        if (name) req.user.name = name;
        if (newPassword) req.user.password = await bcrypt.hash(newPassword, 10);
        if (req.file) req.user.avatar = `/uploads/avatars/${req.file.filename}`;
        
        await req.user.save();
        res.json({ user: { id: req.user._id, name: req.user.name, email: req.user.email, avatar: req.user.avatar } });
    } catch (e) { res.status(500).json({ error: 'Update failed' }); }
});

// Get User Profile (Public View)
app.get('/api/users/:userId', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).select('name avatar status email createdAt');
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (e) { res.status(500).json({ error: 'Error fetching user' }); }
});

// Block User
app.post('/api/users/block/:userId', authenticate, async (req, res) => {
    try {
        const userIdToBlock = req.params.userId;
        if (!req.user.blockedUsers.includes(userIdToBlock)) {
            req.user.blockedUsers.push(userIdToBlock);
            await req.user.save();
        }
        res.json({ message: 'User blocked' });
    } catch (e) { res.status(500).json({ error: 'Failed to block' }); }
});

// Unblock User
app.post('/api/users/unblock/:userId', authenticate, async (req, res) => {
    try {
        req.user.blockedUsers = req.user.blockedUsers.filter(id => id.toString() !== req.params.userId);
        await req.user.save();
        res.json({ message: 'User unblocked' });
    } catch (e) { res.status(500).json({ error: 'Failed to unblock' }); }
});

// Get Chats
app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({ participants: req.user._id })
            .populate('participants', 'name avatar status')
            .populate('lastMessage')
            .sort({ updatedAt: -1 }); // Latest on top
        res.json(chats);
    } catch (e) { res.status(500).json({ error: 'Failed chats' }); }
});

// Get Messages
app.get('/api/chats/:chatId/messages', authenticate, async (req, res) => {
    try {
        const messages = await Message.find({ chat: req.params.chatId }).populate('sender', 'name avatar');
        res.json(messages);
    } catch (e) { res.status(500).json({ error: 'Failed messages' }); }
});

// Send Message
app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text } = req.body;
        const chat = await Chat.findById(chatId);
        
        // Check if blocked
        const otherUserId = chat.participants.find(p => !p.equals(req.user._id));
        const otherUser = await User.findById(otherUserId);
        if (otherUser.blockedUsers.includes(req.user._id)) {
            return res.status(403).json({ error: 'You are blocked by this user' });
        }

        const message = new Message({ chat: chatId, sender: req.user._id, text });
        await message.save();
        
        chat.lastMessage = message._id;
        chat.updatedAt = Date.now();
        await chat.save();
        
        const populatedMsg = await message.populate('sender', 'name avatar');
        
        io.to(chatId).emit('new_message', populatedMsg);
        // Also emit to update chat list order
        io.emit('chat_updated', { chatId, lastMessage: populatedMsg }); 

        res.json(populatedMsg);
    } catch (e) { res.status(500).json({ error: 'Send failed' }); }
});

// Edit Message
app.put('/api/messages/:msgId', authenticate, async (req, res) => {
    try {
        const { text } = req.body;
        const msg = await Message.findById(req.params.msgId);
        if (!msg.sender.equals(req.user._id)) return res.status(403).json({ error: 'Not authorized' });
        
        msg.text = text;
        msg.edited = true;
        await msg.save();
        
        io.to(msg.chat.toString()).emit('message_updated', { _id: msg._id, text: msg.text, edited: true });
        res.json(msg);
    } catch (e) { res.status(500).json({ error: 'Edit failed' }); }
});

// Create/Get Chat (Single Chat Box Logic)
app.post('/api/chats', authenticate, async (req, res) => {
    try {
        const { userId } = req.body;
        // Check if chat exists
        let chat = await Chat.findOne({
            participants: { $all: [req.user._id, userId] }
        }).populate('participants', 'name avatar');

        if (!chat) {
            chat = new Chat({ participants: [req.user._id, userId] });
            await chat.save();
            await chat.populate('participants', 'name avatar');
        }
        res.json(chat);
    } catch (e) { res.status(500).json({ error: 'Create chat failed' }); }
});

// Search Users
app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        const query = req.query.q;
        const users = await User.find({
            _id: { $ne: req.user._id },
            name: { $regex: query, $options: 'i' }
        }).select('name email avatar');
        res.json(users);
    } catch (e) { res.status(500).json({ error: 'Search failed' }); }
});

// Remove Friend (Simplified: Just delete chat to "remove" connection visually)
app.delete('/api/friends/:friendId', authenticate, async (req, res) => {
    try {
         // Logic can be expanded, currently just removing chat history effectively hides them
        const chat = await Chat.findOne({ participants: { $all: [req.user._id, req.params.friendId] }});
        if(chat) {
            await Message.deleteMany({ chat: chat._id }); // Optional: Delete messages
            await Chat.findByIdAndDelete(chat._id);
        }
        res.json({ message: 'Removed' });
    } catch (e) { res.status(500).json({ error: 'Remove failed' }); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server on ${PORT}`));

// Socket Logic
const userSockets = new Map();

io.on('connection', (socket) => {
    socket.on('join_user', (userId) => {
        socket.join(userId);
        userSockets.set(userId, socket.id);
        User.findByIdAndUpdate(userId, { status: 'online' }).exec();
    });

    socket.on('join_chat', (chatId) => {
        socket.join(chatId);
    });
    
    socket.on('leave_chat', (chatId) => {
        socket.leave(chatId);
    });

    socket.on('disconnect', () => {
        // Handle offline status
    });
});