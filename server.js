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
        origin: "*", // In production, replace with your client URL
        methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling']
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox_chat';
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('? MongoDB Connected Successfully'))
.catch(err => console.error('? MongoDB Error:', err));

// ===== MODELS =====
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true, trim: true, minlength: 3 },
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    avatar: { type: String, default: null },
    status: { type: String, enum: ['online', 'offline'], default: 'offline' },
    bio: { type: String, default: '' },
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    lastSeen: { type: Date, default: Date.now }
}, { timestamps: true });

const FriendRequestSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' }
}, { timestamps: true });

const ChatSchema = new mongoose.Schema({
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
    lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
}, { timestamps: true });

const MessageSchema = new mongoose.Schema({
    chat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    status: { type: String, enum: ['sending', 'sent', 'delivered', 'read'], default: 'sent' },
    readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Message = mongoose.model('Message', MessageSchema);

// ===== FILE UPLOAD =====
const uploadDir = path.join(__dirname, 'uploads', 'avatars');
if (!fs.existsSync(uploadDir)) {
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
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only image files are allowed'));
    }
});

// ===== JWT CONFIG =====
const JWT_SECRET = process.env.JWT_SECRET || 'learnox-super-secret-key-2024';

// ===== AUTH MIDDLEWARE =====
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

// ===== SOCKET.IO LOGIC =====
const userSockets = new Map(); // Map<UserId, SocketId>

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
    const userId = socket.userId;
    console.log(`User connected: ${userId}`);
    
    // Store socket mapping
    userSockets.set(userId, socket.id);
    
    // Update status to online
    User.findByIdAndUpdate(userId, { status: 'online' }).then(() => {
        socket.broadcast.emit('user_status_changed', { userId, status: 'online' });
    });
    
    // Join a specific chat room
    socket.on('join_chat', (chatId) => {
        socket.join(chatId);
        // console.log(`User ${userId} joined chat ${chatId}`);
    });
    
    // Typing indicators
    socket.on('typing', async ({ chatId }) => {
        const user = await User.findById(userId).select('name');
        socket.to(chatId).emit('typing', { chatId, userId, userName: user?.name || 'User' });
    });
    
    socket.on('typing_stopped', ({ chatId }) => {
        socket.to(chatId).emit('typing_stopped', { chatId, userId });
    });
    
    // Message Read Status
    socket.on('message_seen', async ({ chatId }) => {
        // Mark all messages in this chat sent by OTHERS as read by ME
        await Message.updateMany(
            { chat: chatId, sender: { $ne: userId }, readBy: { $ne: userId } },
            { $addToSet: { readBy: userId }, status: 'read' }
        );
        
        // Notify the sender that I read their messages
        const chat = await Chat.findById(chatId);
        if(chat) {
            const otherParticipants = chat.participants.filter(p => p.toString() !== userId);
            otherParticipants.forEach(pId => {
                const sockId = userSockets.get(pId.toString());
                if(sockId) io.to(sockId).emit('messages_read_update', { chatId, readerId: userId });
            });
        }
    });
    
    socket.on('disconnect', async () => {
        userSockets.delete(userId);
        await User.findByIdAndUpdate(userId, { status: 'offline', lastSeen: new Date() });
        socket.broadcast.emit('user_status_changed', { userId, status: 'offline' });
        console.log(`User disconnected: ${userId}`);
    });
});

// ===== API ROUTES =====

// 1. REGISTER (Username, Name, Email, Password)
app.post('/api/register', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;
        
        if (!username || !name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        // Check duplicates
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'Username or Email already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, name, email, password: hashedPassword });
        await user.save();
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.status(201).json({
            token,
            user: { id: user._id, username: user.username, name: user.name, email: user.email, avatar: user.avatar }
        });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed. Try again.' });
    }
});

// 2. LOGIN (Email and Password ONLY)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and Password are required' });
        }

        // Find by email strictly
        const user = await User.findOne({ email: email.toLowerCase() });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Update status logic
        user.status = 'online';
        await user.save();
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            token,
            user: { id: user._id, username: user.username, name: user.name, email: user.email, avatar: user.avatar, status: user.status }
        });
        
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// 3. VERIFY TOKEN
app.get('/api/verify-token', authenticate, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// 4. SEARCH USERS
app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q || q.length < 2) return res.json([]);
        
        const users = await User.find({
            _id: { $ne: req.user._id, $nin: req.user.blockedUsers },
            $or: [
                { username: { $regex: q, $options: 'i' } },
                { name: { $regex: q, $options: 'i' } },
                { email: { $regex: q, $options: 'i' } }
            ]
        }).select('username name avatar status email').limit(20);
        
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// 5. FRIEND REQUESTS (Send, Get, Accept)
app.post('/api/friend-requests/send', authenticate, async (req, res) => {
    try {
        const { receiverId } = req.body;
        if (receiverId === req.user._id.toString()) return res.status(400).json({ error: 'Cannot add yourself' });

        const exists = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: receiverId },
                { sender: receiverId, receiver: req.user._id }
            ]
        });

        if (exists) return res.status(400).json({ error: 'Request pending or already friends' });

        const request = await FriendRequest.create({ sender: req.user._id, receiver: receiverId });
        
        // Real-time notification
        const receiverSocket = userSockets.get(receiverId);
        if (receiverSocket) {
            const senderInfo = await User.findById(req.user._id).select('name username avatar');
            io.to(receiverSocket).emit('friend_request_received', { sender: senderInfo });
        }

        res.json({ message: 'Request sent' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send request' });
    }
});

app.get('/api/friend-requests/received', authenticate, async (req, res) => {
    const requests = await FriendRequest.find({ receiver: req.user._id, status: 'pending' })
        .populate('sender', 'username name avatar status');
    res.json(requests);
});

app.post('/api/friend-requests/:requestId/:action', authenticate, async (req, res) => {
    try {
        const { requestId, action } = req.params;
        const request = await FriendRequest.findById(requestId);
        
        if (!request) return res.status(404).json({ error: 'Request not found' });
        
        if (action === 'accept') {
            request.status = 'accepted';
            await request.save();
            
            // Create Chat Room automatically
            const chat = await Chat.create({ participants: [request.sender, request.receiver] });
            
            // Notify Sender
            const senderSocket = userSockets.get(request.sender.toString());
            if (senderSocket) io.to(senderSocket).emit('friend_request_accepted', { accepter: req.user.name });
            
        } else {
            await FriendRequest.findByIdAndDelete(requestId); // Delete on reject
        }
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Action failed' });
    }
});

// 6. GET FRIENDS & CHATS
app.get('/api/friends', authenticate, async (req, res) => {
    try {
        const friendsRel = await FriendRequest.find({
            $or: [{ sender: req.user._id }, { receiver: req.user._id }],
            status: 'accepted'
        }).populate('sender receiver', 'username name avatar status email');
        
        const friends = friendsRel.map(r => r.sender._id.equals(req.user._id) ? r.receiver : r.sender);
        res.json(friends);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching friends' });
    }
});

app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({ participants: req.user._id })
            .populate('participants', 'username name avatar status')
            .populate({ path: 'lastMessage', select: 'text createdAt status sender' })
            .sort({ updatedAt: -1 });

        // Format for frontend
        const result = chats.map(chat => {
            const other = chat.participants.find(p => !p._id.equals(req.user._id));
            return {
                _id: chat._id,
                otherParticipant: other,
                lastMessage: chat.lastMessage,
                updatedAt: chat.updatedAt
            };
        });
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching chats' });
    }
});

// 7. MESSAGING
app.get('/api/chats/:chatId/messages', authenticate, async (req, res) => {
    try {
        const messages = await Message.find({ chat: req.params.chatId })
            .populate('sender', 'name username avatar')
            .sort({ createdAt: 1 });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching messages' });
    }
});

app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text } = req.body;
        
        const message = await Message.create({
            chat: chatId,
            sender: req.user._id,
            text,
            status: 'sent'
        });

        await Chat.findByIdAndUpdate(chatId, { lastMessage: message._id, updatedAt: Date.now() });
        
        // Populate and broadcast
        await message.populate('sender', 'username name avatar');
        
        // Send to everyone in room via Socket
        io.to(chatId).emit('new_message', { message, chatId });
        
        res.json(message);
    } catch (error) {
        res.status(500).json({ error: 'Failed to send' });
    }
});

// 8. PROFILE & SETTINGS
app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, currentPassword, newPassword } = req.body;
        const user = req.user;

        if (name) user.name = name;
        if (req.file) user.avatar = `/uploads/avatars/${req.file.filename}`;
        
        if (currentPassword && newPassword) {
            const valid = await bcrypt.compare(currentPassword, user.password);
            if (!valid) return res.status(400).json({ error: 'Incorrect current password' });
            user.password = await bcrypt.hash(newPassword, 10);
        }

        await user.save();
        res.json({ user: { id: user._id, username: user.username, name: user.name, email: user.email, avatar: user.avatar } });
    } catch (error) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.post('/api/chats', authenticate, async (req, res) => {
    // Create/Get chat with friend
    const { userId } = req.body;
    let chat = await Chat.findOne({ participants: { $all: [req.user._id, userId] } });
    
    if (!chat) {
        // Verify friendship first
        const isFriend = await FriendRequest.findOne({
             $or: [{sender: req.user._id, receiver: userId}, {sender: userId, receiver: req.user._id}],
             status: 'accepted'
        });
        if(!isFriend) return res.status(403).json({ error: 'Must be friends to chat' });

        chat = await Chat.create({ participants: [req.user._id, userId] });
    }
    res.json(chat);
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`?? Server running on http://localhost:${PORT}`);
});