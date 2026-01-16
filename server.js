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

// Socket.io
const io = socketIo(server, {
    cors: {
        origin: "*",
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

// MongoDB
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox_chat';
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('? MongoDB Connected'))
.catch(err => console.error('? MongoDB Error:', err));

// ===== MODELS =====
const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        minlength: 3,
        maxlength: 20
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    avatar: {
        type: String,
        default: null
    },
    status: {
        type: String,
        enum: ['online', 'offline'],
        default: 'offline'
    },
    bio: {
        type: String,
        default: ''
    },
    blockedUsers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    lastSeen: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

const FriendRequestSchema = new mongoose.Schema({
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    receiver: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'accepted', 'rejected'],
        default: 'pending'
    }
}, {
    timestamps: true
});

const ChatSchema = new mongoose.Schema({
    participants: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }],
    lastMessage: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Message'
    }
}, {
    timestamps: true
});

const MessageSchema = new mongoose.Schema({
    chat: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Chat',
        required: true
    },
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    text: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['sending', 'sent', 'delivered', 'read'],
        default: 'sent'
    },
    readBy: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }]
}, {
    timestamps: true
});

const User = mongoose.model('User', UserSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Message = mongoose.model('Message', MessageSchema);

// ===== FILE UPLOAD =====
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = path.join(uploadDir, 'avatars');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
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

// ===== JWT CONFIG =====
const JWT_SECRET = process.env.JWT_SECRET || 'learnox-secret-key-2024';

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

// ===== SOCKET.IO =====
const userSockets = new Map();

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
    console.log('User connected:', userId);
    
    // Store socket
    userSockets.set(userId, socket.id);
    
    // Update status
    User.findByIdAndUpdate(userId, { status: 'online' }).then(() => {
        socket.broadcast.emit('user_status_changed', { userId, status: 'online' });
    });
    
    // Join chat room
    socket.on('join_chat', (chatId) => {
        socket.join(chatId);
    });
    
    // Typing indicator
    socket.on('typing', async (data) => {
        const { chatId, userName } = data;
        const user = await User.findById(userId);
        socket.to(chatId).emit('typing', { chatId, userId, userName: user.name });
    });
    
    socket.on('typing_stopped', (data) => {
        socket.to(data.chatId).emit('typing_stopped', data);
    });
    
    // Message seen
    socket.on('message_seen', async (data) => {
        const { chatId } = data;
        
        await Message.updateMany(
            { chat: chatId, sender: { $ne: userId }, status: { $in: ['sent', 'delivered'] } },
            { $addToSet: { readBy: userId }, status: 'read' }
        );
        
        // Notify sender
        const messages = await Message.find({ chat: chatId, sender: { $ne: userId } });
        messages.forEach(msg => {
            const senderSocket = userSockets.get(msg.sender.toString());
            if (senderSocket) {
                io.to(senderSocket).emit('message_read', {
                    messageId: msg._id,
                    chatId,
                    readerId: userId
                });
            }
        });
    });
    
    // Disconnect
    socket.on('disconnect', async () => {
        userSockets.delete(userId);
        await User.findByIdAndUpdate(userId, { status: 'offline' });
        socket.broadcast.emit('user_status_changed', { userId, status: 'offline' });
    });
});

// ===== API ROUTES =====

// Check username availability (NO AUTH REQUIRED)
app.get('/api/check-username/:username', async (req, res) => {
    try {
        const { username } = req.params;
        
        if (!username || username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }
        
        const existingUser = await User.findOne({ 
            username: username.toLowerCase() 
        });
        
        res.json({ 
            available: !existingUser 
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;
        
        // Validation
        if (!username || !name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        // Check existing user
        const existingUser = await User.findOne({
            $or: [{ username: username.toLowerCase() }, { email: email.toLowerCase() }]
        });
        
        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        // Create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username: username.toLowerCase(),
            name,
            email: email.toLowerCase(),
            password: hashedPassword
        });
        
        await user.save();
        
        // Generate token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                name: user.name,
                email: user.email,
                avatar: user.avatar,
                status: user.status
            }
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user
        const user = await User.findOne({
            $or: [
                { username: username.toLowerCase() },
                { email: username.toLowerCase() }
            ]
        });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Update last seen
        user.lastSeen = new Date();
        await user.save();
        
        // Generate token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                name: user.name,
                email: user.email,
                avatar: user.avatar,
                status: user.status
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify token
app.get('/api/verify-token', authenticate, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// Search users
app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        const { q = '' } = req.query;
        
        if (!q || q.trim().length < 2) {
            return res.json([]);
        }
        
        const searchQuery = q.trim().toLowerCase();
        
        // Exclude current user and blocked users
        const users = await User.find({
            _id: { $ne: req.user._id, $nin: req.user.blockedUsers },
            $or: [
                { username: { $regex: searchQuery, $options: 'i' } },
                { name: { $regex: searchQuery, $options: 'i' } }
            ]
        })
        .select('username name avatar status')
        .limit(20);
        
        res.json(users);
        
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Get user by ID
app.get('/api/users/:userId', authenticate, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const user = await User.findById(userId)
            .select('username name avatar status bio lastSeen');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get user' });
    }
});

// Send friend request
app.post('/api/friend-requests/send', authenticate, async (req, res) => {
    try {
        const { receiverId } = req.body;
        
        if (!receiverId) {
            return res.status(400).json({ error: 'Receiver ID required' });
        }
        
        if (receiverId === req.user._id.toString()) {
            return res.status(400).json({ error: 'Cannot add yourself' });
        }
        
        // Check if already friends
        const existingRequest = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: receiverId },
                { sender: receiverId, receiver: req.user._id }
            ]
        });
        
        if (existingRequest) {
            if (existingRequest.status === 'accepted') {
                return res.status(400).json({ error: 'Already friends' });
            }
            return res.status(400).json({ error: 'Request already pending' });
        }
        
        // Create request
        const request = new FriendRequest({
            sender: req.user._id,
            receiver: receiverId
        });
        
        await request.save();
        
        // Populate sender
        await request.populate('sender', 'username name avatar');
        
        // Notify receiver
        const receiverSocket = userSockets.get(receiverId);
        if (receiverSocket) {
            io.to(receiverSocket).emit('friend_request_received', {
                request,
                sender: request.sender
            });
        }
        
        res.json({ message: 'Friend request sent' });
        
    } catch (error) {
        console.error('Send friend request error:', error);
        res.status(500).json({ error: 'Failed to send request' });
    }
});

// Get friend requests
app.get('/api/friend-requests/received', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({ 
            receiver: req.user._id, 
            status: 'pending' 
        })
        .populate('sender', 'username name avatar status');
        
        res.json(requests);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get requests' });
    }
});

app.get('/api/friend-requests/sent', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({ 
            sender: req.user._id, 
            status: 'pending' 
        })
        .populate('receiver', 'username name avatar status');
        
        res.json(requests);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get requests' });
    }
});

// Accept/reject friend request
app.post('/api/friend-requests/:requestId/:action', authenticate, async (req, res) => {
    try {
        const { requestId, action } = req.params;
        
        const request = await FriendRequest.findById(requestId);
        if (!request) {
            return res.status(404).json({ error: 'Request not found' });
        }
        
        if (action === 'accept') {
            request.status = 'accepted';
            await request.save();
            
            // Create chat
            const chat = new Chat({
                participants: [request.sender, request.receiver]
            });
            await chat.save();
            
            // Notify sender
            const senderSocket = userSockets.get(request.sender.toString());
            if (senderSocket) {
                io.to(senderSocket).emit('friend_request_accepted', {
                    acceptorId: req.user._id,
                    acceptorName: req.user.name
                });
            }
        } else if (action === 'reject') {
            request.status = 'rejected';
            await request.save();
        }
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// Get friends
app.get('/api/friends', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({
            $or: [
                { sender: req.user._id, status: 'accepted' },
                { receiver: req.user._id, status: 'accepted' }
            ]
        })
        .populate('sender receiver', 'username name avatar status');
        
        const friends = requests.map(request => 
            request.sender._id.equals(req.user._id) ? request.receiver : request.sender
        );
        
        res.json(friends);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get friends' });
    }
});

// Remove friend
app.delete('/api/friends/:friendId', authenticate, async (req, res) => {
    try {
        const { friendId } = req.params;
        
        // Remove friend request
        await FriendRequest.findOneAndDelete({
            $or: [
                { sender: req.user._id, receiver: friendId, status: 'accepted' },
                { sender: friendId, receiver: req.user._id, status: 'accepted' }
            ]
        });
        
        // Delete chat
        await Chat.findOneAndDelete({
            participants: { $all: [req.user._id, friendId] }
        });
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove friend' });
    }
});

// Create or get chat
app.post('/api/chats', authenticate, async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'User ID required' });
        }
        
        // Check if already friends
        const areFriends = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: userId, status: 'accepted' },
                { sender: userId, receiver: req.user._id, status: 'accepted' }
            ]
        });
        
        if (!areFriends) {
            return res.status(403).json({ error: 'You can only chat with friends' });
        }
        
        // Find existing chat
        let chat = await Chat.findOne({
            participants: { $all: [req.user._id, userId] }
        });
        
        if (!chat) {
            chat = new Chat({
                participants: [req.user._id, userId]
            });
            await chat.save();
        }
        
        await chat.populate('participants', 'username name avatar status');
        
        res.json(chat);
        
    } catch (error) {
        console.error('Create chat error:', error);
        res.status(500).json({ error: 'Failed to create chat' });
    }
});

// Get user chats
app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({ participants: req.user._id })
            .populate('participants', 'username name avatar status')
            .populate('lastMessage')
            .sort({ updatedAt: -1 });
        
        // Add other participant info
        const chatsWithDetails = chats.map(chat => {
            const otherParticipant = chat.participants.find(p => !p._id.equals(req.user._id));
            return {
                ...chat.toObject(),
                otherParticipant
            };
        });
        
        res.json(chatsWithDetails);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get chats' });
    }
});

// Get chat messages
app.get('/api/chats/:chatId/messages', authenticate, async (req, res) => {
    try {
        const { chatId } = req.params;
        
        // Verify user is participant
        const chat = await Chat.findById(chatId);
        if (!chat || !chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const messages = await Message.find({ chat: chatId })
            .populate('sender', 'username name avatar')
            .sort({ createdAt: 1 });
        
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

// Send message
app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text } = req.body;
        
        if (!chatId || !text) {
            return res.status(400).json({ error: 'Chat ID and text required' });
        }
        
        // Verify chat
        const chat = await Chat.findById(chatId);
        if (!chat || !chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // Create message
        const message = new Message({
            chat: chatId,
            sender: req.user._id,
            text
        });
        
        await message.save();
        
        // Update chat's last message
        chat.lastMessage = message._id;
        chat.updatedAt = new Date();
        await chat.save();
        
        // Populate sender
        await message.populate('sender', 'username name avatar');
        
        // Broadcast to participants
        chat.participants.forEach(participantId => {
            const participantSocket = userSockets.get(participantId.toString());
            if (participantSocket) {
                io.to(participantSocket).emit('new_message', {
                    message,
                    chatId
                });
            }
        });
        
        res.json(message);
        
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Block user
app.post('/api/users/block/:userId', authenticate, async (req, res) => {
    try {
        const { userId } = req.params;
        
        if (userId === req.user._id.toString()) {
            return res.status(400).json({ error: 'Cannot block yourself' });
        }
        
        // Add to blocked list
        if (!req.user.blockedUsers.includes(userId)) {
            req.user.blockedUsers.push(userId);
            await req.user.save();
        }
        
        // Remove friend request
        await FriendRequest.findOneAndDelete({
            $or: [
                { sender: req.user._id, receiver: userId },
                { sender: userId, receiver: req.user._id }
            ]
        });
        
        // Delete chat
        await Chat.findOneAndDelete({
            participants: { $all: [req.user._id, userId] }
        });
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to block user' });
    }
});

// Unblock user
app.delete('/api/users/block/:userId', authenticate, async (req, res) => {
    try {
        const { userId } = req.params;
        
        req.user.blockedUsers = req.user.blockedUsers.filter(id => 
            id.toString() !== userId
        );
        
        await req.user.save();
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to unblock user' });
    }
});

// Get blocked users
app.get('/api/blocked-users', authenticate, async (req, res) => {
    try {
        const users = await User.find({
            _id: { $in: req.user.blockedUsers }
        }).select('username name avatar');
        
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get blocked users' });
    }
});

// Update profile
app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, currentPassword, newPassword } = req.body;
        
        if (name) req.user.name = name;
        
        // Handle password change
        if (currentPassword && newPassword) {
            const isValid = await bcrypt.compare(currentPassword, req.user.password);
            if (!isValid) {
                return res.status(400).json({ error: 'Current password is incorrect' });
            }
            
            if (newPassword.length < 6) {
                return res.status(400).json({ error: 'New password must be at least 6 characters' });
            }
            
            req.user.password = await bcrypt.hash(newPassword, 10);
        }
        
        // Handle avatar
        if (req.file) {
            req.user.avatar = `/uploads/avatars/${req.file.filename}`;
        }
        
        await req.user.save();
        
        // Remove password from response
        const userData = req.user.toObject();
        delete userData.password;
        
        res.json({ user: userData });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Delete account
app.delete('/api/account/delete', authenticate, async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password required' });
        }
        
        // Verify password
        const isValid = await bcrypt.compare(password, req.user.password);
        if (!isValid) {
            return res.status(400).json({ error: 'Incorrect password' });
        }
        
        // Delete user data
        await Promise.all([
            User.findByIdAndDelete(req.user._id),
            FriendRequest.deleteMany({
                $or: [{ sender: req.user._id }, { receiver: req.user._id }]
            }),
            Message.deleteMany({ sender: req.user._id }),
            Chat.deleteMany({ participants: req.user._id })
        ]);
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

// 404 handler
app.use('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`?? Server running on port ${PORT}`);
});