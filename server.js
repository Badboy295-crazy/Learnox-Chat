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

// Socket.io Setup
const io = socketIo(server, {
    cors: {
        origin: "*", 
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(cors());
app.use(express.json());

// Serving Static Files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox';
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected Successfully'))
.catch(err => console.error('MongoDB Connection Error:', err));

// --- MODELS ---

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String },
    status: { type: String, default: 'offline' }, // online, offline
    chatBackground: { type: String, default: 'default' },
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // New: Blocking logic
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
    // Removed unreadCount Map to calculate dynamically for accuracy
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
    chat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    status: { type: String, enum: ['sending', 'sent', 'delivered', 'seen'], default: 'sending' },
    edited: { type: Boolean, default: false },
    deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Message = mongoose.model('Message', MessageSchema);

// File Upload Setup
const uploadDir = 'uploads/avatars/';
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) return cb(null, true);
        cb(new Error('Only image files are allowed'));
    }
});

const JWT_SECRET = process.env.JWT_SECRET || 'learnox-super-secret-key';

// --- AUTH MIDDLEWARE ---
const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error();
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        if (!user) throw new Error();
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

const authorizeChatAccess = async (req, res, next) => {
    try {
        const chat = await Chat.findById(req.params.chatId);
        if (!chat) return res.status(404).json({ error: 'Chat not found' });
        if (!chat.participants.includes(req.user._id)) return res.status(403).json({ error: 'Access denied' });
        req.chat = chat;
        next();
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
};

// --- SOCKET LOGIC ---
const userSockets = new Map(); // userId -> socketId

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error'));
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userId = decoded.userId;
        next();
    } catch (error) {
        next(new Error('Authentication error'));
    }
});

io.on('connection', (socket) => {
    console.log('User connected:', socket.userId);
    
    socket.join(socket.userId);
    userSockets.set(socket.userId, socket.id);

    User.findByIdAndUpdate(socket.userId, { status: 'online' }).then(() => {
        io.emit('user_status_changed', { userId: socket.userId, status: 'online' });
    });

    socket.on('join_chat', (chatId) => {
        socket.join(chatId);
    });

    socket.on('typing', (data) => {
        socket.to(data.chatId).emit('typing', data);
    });

    socket.on('disconnect', async () => {
        userSockets.delete(socket.userId);
        await User.findByIdAndUpdate(socket.userId, { status: 'offline' });
        io.emit('user_status_changed', { userId: socket.userId, status: 'offline' });
    });
});

// --- API ROUTES ---

// Auth
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if(await User.findOne({ email })) return res.status(400).json({ error: 'User already exists' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar } });
    } catch (error) { res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar, status: user.status } });
    } catch (error) { res.status(500).json({ error: 'Login failed' }); }
});

// Profile
app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, currentPassword, newPassword } = req.body;
        const user = req.user;

        if (!(await bcrypt.compare(currentPassword, user.password))) {
            return res.status(401).json({ error: 'Current password incorrect' });
        }

        if (name) user.name = name;
        // Email change removed for security as requested
        
        if (newPassword) user.password = await bcrypt.hash(newPassword, 10);
        
        if (req.file) {
            if (user.avatar && user.avatar.startsWith('/uploads')) {
                const oldPath = path.join(__dirname, user.avatar.substring(1));
                if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
            }
            user.avatar = `/uploads/avatars/${req.file.filename}`;
        }
        await user.save();
        res.json({ user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar, status: user.status } });
    } catch (error) { res.status(500).json({ error: 'Update failed' }); }
});

// View Other Profile
app.get('/api/users/:userId', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).select('name email avatar status createdAt');
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (error) { res.status(500).json({ error: 'Error fetching profile' }); }
});

// Friends & Blocking
app.get('/api/friends', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({
            $or: [ { sender: req.user._id, status: 'accepted' }, { receiver: req.user._id, status: 'accepted' } ]
        }).populate('sender receiver', 'name email avatar status');

        // Filter out blocked users
        const blockedIds = req.user.blockedUsers.map(id => id.toString());
        
        const friends = requests.map(reqData => {
            const friend = reqData.sender._id.equals(req.user._id) ? reqData.receiver : reqData.sender;
            return friend;
        }).filter(f => !blockedIds.includes(f._id.toString()));

        const formattedFriends = friends.map(f => ({
            id: f._id, name: f.name, email: f.email, avatar: f.avatar, status: f.status
        }));
        res.json(formattedFriends);
    } catch (error) { res.status(500).json({ error: 'Fetch friends failed' }); }
});

app.post('/api/users/block/:userId', authenticate, async (req, res) => {
    try {
        const userIdToBlock = req.params.userId;
        if (!req.user.blockedUsers.includes(userIdToBlock)) {
            req.user.blockedUsers.push(userIdToBlock);
            await req.user.save();
        }
        res.json({ message: 'User blocked' });
    } catch (error) { res.status(500).json({ error: 'Block failed' }); }
});

app.delete('/api/friends/:friendId', authenticate, async (req, res) => {
    try {
        const friendId = req.params.friendId;
        await FriendRequest.deleteMany({
            $or: [
                { sender: req.user._id, receiver: friendId },
                { sender: friendId, receiver: req.user._id }
            ]
        });
        // Optionally delete chat or keep it
        res.json({ message: 'Friend removed' });
    } catch (error) { res.status(500).json({ error: 'Remove friend failed' }); }
});

// Friend Requests
app.post('/api/friend-requests/send', authenticate, async (req, res) => {
    try {
        const { receiverId } = req.body;
        // Check if blocked
        const receiver = await User.findById(receiverId);
        if (receiver.blockedUsers.includes(req.user._id)) return res.status(403).json({ error: 'Cannot send request' });
        
        const existing = await FriendRequest.findOne({
            $or: [ { sender: req.user._id, receiver: receiverId }, { sender: receiverId, receiver: req.user._id } ]
        });
        if (existing) return res.status(400).json({ error: 'Request exists or already friends' });

        const request = new FriendRequest({ sender: req.user._id, receiver: receiverId });
        await request.save();
        await request.populate('sender', 'name email');

        const sock = userSockets.get(receiverId);
        if (sock) io.to(sock).emit('friend_request_received', { _id: request._id, senderName: request.sender.name, sender: request.sender });
        
        res.json(request);
    } catch (error) { res.status(500).json({ error: 'Request failed' }); }
});

app.get('/api/friend-requests/received', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({ receiver: req.user._id, status: 'pending' }).populate('sender', 'name email avatar');
        res.json(requests);
    } catch (error) { res.status(500).json({ error: 'Fetch failed' }); }
});

app.post('/api/friend-requests/:requestId/:action', authenticate, async (req, res) => {
    try {
        const { action } = req.params; // accept or reject
        const request = await FriendRequest.findById(req.params.requestId);
        if (!request) return res.status(404).json({ error: 'Not found' });
        
        if (action === 'accept') {
            request.status = 'accepted';
            await request.save();
            const sock = userSockets.get(request.sender.toString());
            if (sock) io.to(sock).emit('friend_request_accepted', { acceptorName: req.user.name });
        } else {
            request.status = 'rejected';
            await request.save();
        }
        res.json(request);
    } catch (error) { res.status(500).json({ error: 'Action failed' }); }
});

// Chats
app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({ participants: req.user._id })
            .populate('participants', 'name email avatar status')
            .populate('lastMessage')
            .sort({ updatedAt: -1 });

        const chatsWithData = await Promise.all(chats.map(async (chat) => {
            const unread = await Message.countDocuments({
                chat: chat._id, sender: { $ne: req.user._id }, status: { $in: ['sent', 'delivered'] }
            });
            return { ...chat.toObject(), unreadCount: unread };
        }));
        res.json(chatsWithData);
    } catch (error) { res.status(500).json({ error: 'Fetch chats failed' }); }
});

app.post('/api/chats', authenticate, async (req, res) => {
    try {
        const { userId } = req.body;
        // Check if friend
        const isFriend = await FriendRequest.findOne({
            $or: [ { sender: req.user._id, receiver: userId, status: 'accepted' }, { sender: userId, receiver: req.user._id, status: 'accepted' } ]
        });
        if (!isFriend) return res.status(403).json({ error: 'Friends only' });

        let chat = await Chat.findOne({ participants: { $all: [req.user._id, userId] } });
        if (!chat) {
            chat = new Chat({ participants: [req.user._id, userId] });
            await chat.save();
        }
        await chat.populate('participants', 'name email avatar status');
        res.json(chat);
    } catch (error) { res.status(500).json({ error: 'Create chat failed' }); }
});

app.get('/api/chats/:chatId/messages', authenticate, authorizeChatAccess, async (req, res) => {
    try {
        const messages = await Message.find({ chat: req.params.chatId, deletedFor: { $ne: req.user._id } })
            .populate('sender', 'name email avatar').sort({ createdAt: 1 });
        res.json(messages);
    } catch (error) { res.status(500).json({ error: 'Fetch messages failed' }); }
});

app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text } = req.body;
        const chat = await Chat.findById(chatId);
        if (!chat || !chat.participants.includes(req.user._id)) return res.status(403).json({ error: 'Access denied' });

        // Check if blocked by any participant
        // Simplified: Assume 2 people chat. Check if other blocked me.
        const otherId = chat.participants.find(p => !p.equals(req.user._id));
        const otherUser = await User.findById(otherId);
        if (otherUser && otherUser.blockedUsers.includes(req.user._id)) {
            return res.status(403).json({ error: 'You are blocked by this user' });
        }

        const message = new Message({ chat: chatId, sender: req.user._id, text, status: 'sent' });
        await message.save();
        
        chat.lastMessage = message._id;
        chat.updatedAt = Date.now();
        await chat.save();
        await message.populate('sender', 'name email avatar');

        io.to(chatId).emit('new_message', { ...message.toObject(), senderName: req.user.name });
        
        res.json(message);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Send failed' }); 
    }
});

app.post('/api/chats/:chatId/read', authenticate, authorizeChatAccess, async (req, res) => {
    try {
        await Message.updateMany(
            { chat: req.chat._id, sender: { $ne: req.user._id }, status: { $in: ['sent', 'delivered'] } },
            { status: 'seen' }
        );
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Read failed' }); }
});

app.put('/api/messages/:messageId', authenticate, async (req, res) => {
    try {
        const { text } = req.body;
        const message = await Message.findById(req.params.messageId);
        if (!message.sender.equals(req.user._id)) return res.status(403).json({ error: 'Denied' });
        
        message.text = text;
        message.edited = true;
        await message.save();
        
        io.to(message.chat.toString()).emit('message_updated', { messageId: message._id, chatId: message.chat, text: message.text, edited: true });
        res.json(message);
    } catch (error) { res.status(500).json({ error: 'Update failed' }); }
});

app.delete('/api/messages/:messageId', authenticate, async (req, res) => {
    try {
        const message = await Message.findById(req.params.messageId);
        message.deletedFor.push(req.user._id);
        await message.save();
        io.to(message.chat.toString()).emit('message_deleted', { messageId: message._id, chatId: message.chat });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Delete failed' }); }
});

app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        const q = req.query.q || '';
        const users = await User.find({
            _id: { $ne: req.user._id },
            $or: [ { name: { $regex: q, $options: 'i' } }, { email: { $regex: q, $options: 'i' } } ]
        }).select('name email avatar status');
        res.json(users);
    } catch (error) { res.status(500).json({ error: 'Search failed' }); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));