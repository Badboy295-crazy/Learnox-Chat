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

// Socket.io with improved configuration
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true
    },
    transports: ['websocket', 'polling']
});

// Middleware
app.use(cors({
    origin: "*",
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox_pro';
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('? MongoDB Connected Successfully'))
.catch(err => console.error('? MongoDB Connection Error:', err));

// ===== ENHANCED MODELS =====
const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        minlength: 3,
        maxlength: 20,
        match: /^[a-zA-Z0-9_]+$/
    },
    name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 50
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    },
    password: {
        type: String,
        required: true
    },
    avatar: {
        type: String,
        default: null
    },
    bio: {
        type: String,
        default: '',
        maxlength: 200
    },
    status: {
        type: String,
        enum: ['online', 'offline', 'away', 'busy'],
        default: 'offline'
    },
    lastSeen: {
        type: Date,
        default: Date.now
    },
    chatBackground: {
        type: String,
        default: 'default'
    },
    theme: {
        type: String,
        enum: ['dark', 'light', 'auto'],
        default: 'dark'
    },
    notificationSettings: {
        messageNotifications: { type: Boolean, default: true },
        friendRequestNotifications: { type: Boolean, default: true },
        soundEnabled: { type: Boolean, default: true }
    },
    privacySettings: {
        showOnlineStatus: { type: Boolean, default: true },
        showLastSeen: { type: Boolean, default: true },
        allowFriendRequests: { type: Boolean, default: true }
    },
    blockedUsers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    isActive: {
        type: Boolean,
        default: true
    },
    deletedAt: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

UserSchema.index({ username: 1 });
UserSchema.index({ email: 1 });
UserSchema.index({ status: 1 });

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
        enum: ['pending', 'accepted', 'rejected', 'cancelled'],
        default: 'pending'
    },
    message: {
        type: String,
        maxlength: 200
    }
}, {
    timestamps: true
});

FriendRequestSchema.index({ sender: 1, receiver: 1 });
FriendRequestSchema.index({ status: 1 });

const ChatSchema = new mongoose.Schema({
    participants: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }],
    lastMessage: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Message'
    },
    unreadCount: {
        type: Map,
        of: Number,
        default: {}
    },
    isGroup: {
        type: Boolean,
        default: false
    },
    groupName: String,
    groupAvatar: String,
    groupDescription: String,
    admins: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    settings: {
        allowMedia: { type: Boolean, default: true },
        allowReactions: { type: Boolean, default: true },
        allowEditing: { type: Boolean, default: true }
    }
}, {
    timestamps: true
});

ChatSchema.index({ participants: 1 });
ChatSchema.index({ updatedAt: -1 });

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
        required: true,
        trim: true,
        maxlength: 5000
    },
    messageType: {
        type: String,
        enum: ['text', 'image', 'file', 'audio', 'video', 'location'],
        default: 'text'
    },
    attachments: [{
        url: String,
        filename: String,
        filetype: String,
        size: Number,
        thumbnail: String
    }],
    status: {
        type: String,
        enum: ['sending', 'sent', 'delivered', 'read'],
        default: 'sent'
    },
    readBy: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        readAt: { type: Date, default: Date.now }
    }],
    edited: {
        type: Boolean,
        default: false
    },
    editedAt: Date,
    deletedFor: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    reactions: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        emoji: String,
        reactedAt: { type: Date, default: Date.now }
    }],
    replyTo: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Message'
    },
    forwarded: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

MessageSchema.index({ chat: 1, createdAt: -1 });
MessageSchema.index({ sender: 1 });

const User = mongoose.model('User', UserSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Message = mongoose.model('Message', MessageSchema);

// ===== FILE UPLOAD CONFIGURATION =====
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        let folder = 'general';
        if (file.fieldname === 'avatar') folder = 'avatars';
        else if (file.fieldname === 'attachments') folder = 'attachments';
        
        const dir = path.join(uploadDir, folder);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 20 * 1024 * 1024 // 20MB
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = {
            'avatar': /jpeg|jpg|png|gif|webp/,
            'attachments': /jpeg|jpg|png|gif|webp|pdf|doc|docx|txt|mp3|mp4|wav|ogg|m4a/
        };
        
        const type = file.fieldname;
        const mimetype = allowedTypes[type]?.test(file.mimetype);
        const extname = allowedTypes[type]?.test(path.extname(file.originalname).toLowerCase());
        
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error(`Invalid file type for ${type}`));
    }
});

// ===== JWT CONFIGURATION =====
const JWT_SECRET = process.env.JWT_SECRET || 'learnox-pro-super-secure-jwt-secret-key-2024';
const JWT_EXPIRES_IN = '30d';

// ===== HELPER FUNCTIONS =====
const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

const validateUsername = (username) => {
    return /^[a-zA-Z0-9_]{3,20}$/.test(username);
};

const validatePassword = (password) => {
    return password.length >= 6;
};

const sanitizeUser = (user) => {
    const userObj = user.toObject ? user.toObject() : user;
    delete userObj.password;
    delete userObj.__v;
    return userObj;
};

// ===== AUTHENTICATION MIDDLEWARE =====
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.header('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authentication required. Please login again.' });
        }
        
        const token = authHeader.replace('Bearer ', '');
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const user = await User.findById(decoded.userId);
        if (!user || !user.isActive) {
            return res.status(401).json({ error: 'User account not found or disabled' });
        }
        
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        console.error('Authentication error:', error.message);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Session expired. Please login again.' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid authentication token.' });
        }
        res.status(401).json({ error: 'Authentication failed.' });
    }
};

// ===== SOCKET.IO IMPLEMENTATION =====
const userSockets = new Map(); // userId -> socketId
const typingUsers = new Map(); // chatId -> {userId, timeout}

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication error: No token provided'));
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userId = decoded.userId;
        socket.userData = null;
        next();
    } catch (error) {
        next(new Error('Authentication error: Invalid token'));
    }
});

io.on('connection', async (socket) => {
    const userId = socket.userId;
    console.log(`?? User connected: ${userId}`);
    
    try {
        // Get user data
        const user = await User.findById(userId);
        if (!user) {
            socket.disconnect();
            return;
        }
        
        socket.userData = user;
        userSockets.set(userId, socket.id);
        
        // Update user status
        await User.findByIdAndUpdate(userId, { 
            status: 'online',
            lastSeen: new Date()
        });
        
        // Notify all friends about status change
        const friendRequests = await FriendRequest.find({
            $or: [{ sender: userId }, { receiver: userId }],
            status: 'accepted'
        });
        
        const friendIds = friendRequests.map(req => 
            req.sender.toString() === userId ? req.receiver.toString() : req.sender.toString()
        );
        
        friendIds.forEach(friendId => {
            const friendSocket = userSockets.get(friendId);
            if (friendSocket) {
                io.to(friendSocket).emit('user_status_changed', {
                    userId,
                    status: 'online',
                    lastSeen: new Date()
                });
            }
        });
        
        // Handle chat room joining
        socket.on('join_chat', async (chatId) => {
            socket.join(`chat:${chatId}`);
            
            // Load recent messages for this chat
            const messages = await Message.find({ chat: chatId })
                .sort({ createdAt: -1 })
                .limit(50)
                .populate('sender', 'username name avatar');
            
            socket.emit('chat_history', { chatId, messages: messages.reverse() });
        });
        
        // Handle typing indicators
        socket.on('typing', async (data) => {
            const { chatId } = data;
            
            // Clear previous timeout
            const typingKey = `${chatId}:${userId}`;
            if (typingUsers.has(typingKey)) {
                clearTimeout(typingUsers.get(typingKey));
            }
            
            // Notify other participants
            socket.to(`chat:${chatId}`).emit('typing', {
                chatId,
                userId,
                userName: user.name
            });
            
            // Set timeout to auto-stop typing
            const timeout = setTimeout(() => {
                socket.to(`chat:${chatId}`).emit('typing_stopped', {
                    chatId,
                    userId
                });
                typingUsers.delete(typingKey);
            }, 2000);
            
            typingUsers.set(typingKey, timeout);
        });
        
        socket.on('typing_stopped', (data) => {
            const { chatId } = data;
            const typingKey = `${chatId}:${userId}`;
            
            if (typingUsers.has(typingKey)) {
                clearTimeout(typingUsers.get(typingKey));
                typingUsers.delete(typingKey);
            }
            
            socket.to(`chat:${chatId}`).emit('typing_stopped', {
                chatId,
                userId
            });
        });
        
        // Handle message seen
        socket.on('message_seen', async (data) => {
            const { chatId, messageId } = data;
            
            try {
                const message = await Message.findById(messageId);
                if (!message) return;
                
                // Check if user is participant
                const chat = await Chat.findById(chatId);
                if (!chat || !chat.participants.includes(userId)) return;
                
                // Update read status
                const alreadyRead = message.readBy.some(entry => entry.user.toString() === userId);
                if (!alreadyRead) {
                    message.readBy.push({ user: userId, readAt: new Date() });
                    
                    if (message.readBy.length === chat.participants.length - 1) {
                        message.status = 'read';
                    } else {
                        message.status = 'delivered';
                    }
                    
                    await message.save();
                    
                    // Notify sender
                    if (message.sender.toString() !== userId) {
                        const senderSocket = userSockets.get(message.sender.toString());
                        if (senderSocket) {
                            io.to(senderSocket).emit('message_read', {
                                messageId,
                                chatId,
                                readerId: userId
                            });
                        }
                    }
                }
            } catch (error) {
                console.error('Message seen error:', error);
            }
        });
        
        // Handle disconnection
        socket.on('disconnect', async () => {
            console.log(`?? User disconnected: ${userId}`);
            
            userSockets.delete(userId);
            
            // Update user status
            await User.findByIdAndUpdate(userId, {
                status: 'offline',
                lastSeen: new Date()
            });
            
            // Notify friends about status change
            friendIds.forEach(friendId => {
                const friendSocket = userSockets.get(friendId);
                if (friendSocket) {
                    io.to(friendSocket).emit('user_status_changed', {
                        userId,
                        status: 'offline',
                        lastSeen: new Date()
                    });
                }
            });
            
            // Clear typing timeouts
            for (const [key, timeout] of typingUsers.entries()) {
                if (key.endsWith(`:${userId}`)) {
                    clearTimeout(timeout);
                    typingUsers.delete(key);
                }
            }
        });
        
    } catch (error) {
        console.error('Socket connection error:', error);
        socket.disconnect();
    }
});

// ===== API ROUTES =====

// Health Check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        users: userSockets.size
    });
});

// Check Username Availability
app.get('/api/check-username/:username', async (req, res) => {
    try {
        const { username } = req.params;
        
        if (!validateUsername(username)) {
            return res.status(400).json({ 
                error: 'Username must be 3-20 characters (letters, numbers, underscores only)' 
            });
        }
        
        const existingUser = await User.findOne({ 
            username: username.toLowerCase(),
            isActive: true
        });
        
        res.json({ 
            available: !existingUser 
        });
    } catch (error) {
        console.error('Check username error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;
        
        // Validation
        if (!username || !name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (!validateUsername(username)) {
            return res.status(400).json({ 
                error: 'Username must be 3-20 characters (letters, numbers, underscores only)' 
            });
        }
        
        if (!validatePassword(password)) {
            return res.status(400).json({ 
                error: 'Password must be at least 6 characters long' 
            });
        }
        
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        // Check for existing user
        const existingUser = await User.findOne({
            $or: [
                { username: username.toLowerCase() },
                { email: email.toLowerCase() }
            ]
        });
        
        if (existingUser) {
            return res.status(400).json({ 
                error: 'Username or email already exists' 
            });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Create user
        const user = new User({
            username: username.toLowerCase(),
            name: name.trim(),
            email: email.toLowerCase(),
            password: hashedPassword,
            status: 'offline'
        });
        
        await user.save();
        
        // Generate token
        const token = generateToken(user._id);
        
        res.status(201).json({
            success: true,
            token,
            user: sanitizeUser(user)
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        // Find user by username or email
        const user = await User.findOne({
            $or: [
                { username: username.toLowerCase() },
                { email: username.toLowerCase() }
            ],
            isActive: true
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
        const token = generateToken(user._id);
        
        res.json({
            success: true,
            token,
            user: sanitizeUser(user)
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// Get Current User Profile
app.get('/api/profile', authenticate, async (req, res) => {
    try {
        res.json({
            success: true,
            user: sanitizeUser(req.user)
        });
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Failed to get profile' });
    }
});

// Update Profile
app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, bio, currentPassword, newPassword, theme, notificationSettings, privacySettings } = req.body;
        
        // Update basic info
        if (name && name.trim()) {
            req.user.name = name.trim();
        }
        
        if (bio !== undefined) {
            req.user.bio = bio.trim();
        }
        
        if (theme) {
            req.user.theme = theme;
        }
        
        // Update settings
        if (notificationSettings) {
            req.user.notificationSettings = {
                ...req.user.notificationSettings,
                ...JSON.parse(notificationSettings)
            };
        }
        
        if (privacySettings) {
            req.user.privacySettings = {
                ...req.user.privacySettings,
                ...JSON.parse(privacySettings)
            };
        }
        
        // Handle avatar upload
        if (req.file) {
            req.user.avatar = `/uploads/avatars/${req.file.filename}`;
        }
        
        // Handle password change
        if (currentPassword && newPassword) {
            // Verify current password
            const isValidPassword = await bcrypt.compare(currentPassword, req.user.password);
            if (!isValidPassword) {
                return res.status(400).json({ error: 'Current password is incorrect' });
            }
            
            // Validate new password
            if (!validatePassword(newPassword)) {
                return res.status(400).json({ 
                    error: 'New password must be at least 6 characters long' 
                });
            }
            
            // Hash new password
            req.user.password = await bcrypt.hash(newPassword, 12);
        }
        
        await req.user.save();
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            user: sanitizeUser(req.user)
        });
        
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Delete Account
app.delete('/api/account/delete', authenticate, async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password is required to delete account' });
        }
        
        // Verify password
        const isValidPassword = await bcrypt.compare(password, req.user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Incorrect password' });
        }
        
        // Soft delete user
        req.user.isActive = false;
        req.user.deletedAt = new Date();
        req.user.status = 'offline';
        await req.user.save();
        
        // Delete friend requests
        await FriendRequest.deleteMany({
            $or: [{ sender: req.user._id }, { receiver: req.user._id }]
        });
        
        // Remove from blocked lists
        await User.updateMany(
            { blockedUsers: req.user._id },
            { $pull: { blockedUsers: req.user._id } }
        );
        
        // Notify connected sockets
        const userSocket = userSockets.get(req.user._id.toString());
        if (userSocket) {
            io.to(userSocket).emit('account_deleted');
            const socket = io.sockets.sockets.get(userSocket);
            if (socket) socket.disconnect();
        }
        
        res.json({
            success: true,
            message: 'Account deleted successfully'
        });
        
    } catch (error) {
        console.error('Delete account error:', error);
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

// Search Users
app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        const { q = '' } = req.query;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        if (!q || q.trim().length < 2) {
            return res.json([]);
        }
        
        const searchQuery = q.trim().toLowerCase();
        
        // Build query
        const query = {
            _id: { $ne: req.user._id },
            isActive: true,
            $or: [
                { username: { $regex: searchQuery, $options: 'i' } },
                { name: { $regex: searchQuery, $options: 'i' } },
                { email: { $regex: searchQuery, $options: 'i' } }
            ]
        };
        
        // Exclude blocked users
        if (req.user.blockedUsers && req.user.blockedUsers.length > 0) {
            query._id.$nin = req.user.blockedUsers;
        }
        
        // Execute search
        const users = await User.find(query)
            .select('username name email avatar status bio lastSeen createdAt')
            .sort({ username: 1 })
            .skip(skip)
            .limit(limit);
        
        // Get total count for pagination
        const total = await User.countDocuments(query);
        
        // Check friendship status
        const usersWithStatus = await Promise.all(users.map(async (user) => {
            const userObj = sanitizeUser(user);
            
            // Check if blocked
            const isBlocked = req.user.blockedUsers.includes(user._id);
            
            // Check friendship status
            const friendRequest = await FriendRequest.findOne({
                $or: [
                    { sender: req.user._id, receiver: user._id },
                    { sender: user._id, receiver: req.user._id }
                ]
            });
            
            let relationship = 'none';
            if (friendRequest) {
                if (friendRequest.status === 'accepted') relationship = 'friend';
                else if (friendRequest.status === 'pending') {
                    relationship = friendRequest.sender.equals(req.user._id) ? 'request_sent' : 'request_received';
                }
            }
            
            return {
                ...userObj,
                isBlocked,
                relationship
            };
        }));
        
        res.json({
            users: usersWithStatus,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
        
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Get User Details
app.get('/api/users/:userId', authenticate, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const user = await User.findById(userId)
            .select('username name email avatar status bio lastSeen createdAt');
        
        if (!user || !user.isActive) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const userObj = sanitizeUser(user);
        
        // Check relationship
        const friendRequest = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: userId },
                { sender: userId, receiver: req.user._id }
            ]
        });
        
        let relationship = 'none';
        if (friendRequest) {
            if (friendRequest.status === 'accepted') relationship = 'friend';
            else if (friendRequest.status === 'pending') {
                relationship = friendRequest.sender.equals(req.user._id) ? 'request_sent' : 'request_received';
            }
        }
        
        // Check if blocked
        const isBlockedByYou = req.user.blockedUsers.includes(userId);
        const hasBlockedYou = user.blockedUsers.includes(req.user._id);
        
        res.json({
            ...userObj,
            relationship,
            isBlockedByYou,
            hasBlockedYou,
            canMessage: !isBlockedByYou && !hasBlockedYou && relationship === 'friend'
        });
        
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Failed to get user' });
    }
});

// Friend Requests
app.post('/api/friend-requests/send', authenticate, async (req, res) => {
    try {
        const { receiverId, message } = req.body;
        
        if (!receiverId) {
            return res.status(400).json({ error: 'Receiver ID is required' });
        }
        
        if (receiverId === req.user._id.toString()) {
            return res.status(400).json({ error: 'Cannot send friend request to yourself' });
        }
        
        // Check if receiver exists and is active
        const receiver = await User.findById(receiverId);
        if (!receiver || !receiver.isActive) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Check privacy settings
        if (!receiver.privacySettings?.allowFriendRequests) {
            return res.status(403).json({ error: 'This user is not accepting friend requests' });
        }
        
        // Check if blocked
        if (req.user.blockedUsers.includes(receiverId) || 
            receiver.blockedUsers.includes(req.user._id)) {
            return res.status(403).json({ error: 'Cannot send request to blocked user' });
        }
        
        // Check for existing friend request
        const existingRequest = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: receiverId },
                { sender: receiverId, receiver: req.user._id }
            ]
        });
        
        if (existingRequest) {
            if (existingRequest.status === 'pending') {
                return res.status(400).json({ 
                    error: existingRequest.sender.equals(req.user._id) ? 
                        'Friend request already sent' : 
                        'You have a pending request from this user' 
                });
            }
            if (existingRequest.status === 'accepted') {
                return res.status(400).json({ error: 'Already friends' });
            }
        }
        
        // Create friend request
        const friendRequest = new FriendRequest({
            sender: req.user._id,
            receiver: receiverId,
            message: message?.trim(),
            status: 'pending'
        });
        
        await friendRequest.save();
        await friendRequest.populate('sender', 'username name avatar');
        
        // Notify receiver via socket
        const receiverSocket = userSockets.get(receiverId);
        if (receiverSocket) {
            io.to(receiverSocket).emit('friend_request_received', {
                request: friendRequest,
                sender: friendRequest.sender
            });
        }
        
        // Send notification if enabled
        if (receiver.notificationSettings?.friendRequestNotifications) {
            // You can implement push notifications here
        }
        
        res.json({
            success: true,
            message: 'Friend request sent successfully',
            request: friendRequest
        });
        
    } catch (error) {
        console.error('Send friend request error:', error);
        res.status(500).json({ error: 'Failed to send friend request' });
    }
});

// Get Friend Requests
app.get('/api/friend-requests', authenticate, async (req, res) => {
    try {
        const { type = 'received' } = req.query; // 'sent' or 'received'
        
        let query = {};
        if (type === 'sent') {
            query = { sender: req.user._id, status: 'pending' };
        } else {
            query = { receiver: req.user._id, status: 'pending' };
        }
        
        const requests = await FriendRequest.find(query)
            .populate(type === 'sent' ? 'receiver' : 'sender', 'username name avatar status')
            .sort({ createdAt: -1 });
        
        res.json(requests);
    } catch (error) {
        console.error('Get friend requests error:', error);
        res.status(500).json({ error: 'Failed to get friend requests' });
    }
});

// Accept/Reject Friend Request
app.post('/api/friend-requests/:requestId/:action', authenticate, async (req, res) => {
    try {
        const { requestId, action } = req.params;
        const validActions = ['accept', 'reject'];
        
        if (!validActions.includes(action)) {
            return res.status(400).json({ error: 'Invalid action' });
        }
        
        const friendRequest = await FriendRequest.findById(requestId)
            .populate('sender receiver', 'username name avatar');
        
        if (!friendRequest) {
            return res.status(404).json({ error: 'Friend request not found' });
        }
        
        // Authorization check
        if (!friendRequest.receiver._id.equals(req.user._id)) {
            return res.status(403).json({ error: 'Not authorized to perform this action' });
        }
        
        if (friendRequest.status !== 'pending') {
            return res.status(400).json({ error: 'Friend request already processed' });
        }
        
        // Update status
        friendRequest.status = action === 'accept' ? 'accepted' : 'rejected';
        await friendRequest.save();
        
        // If accepted, create chat
        if (action === 'accept') {
            // Check if chat already exists
            let chat = await Chat.findOne({
                participants: { $all: [friendRequest.sender._id, friendRequest.receiver._id] },
                isGroup: false
            });
            
            if (!chat) {
                chat = new Chat({
                    participants: [friendRequest.sender._id, friendRequest.receiver._id],
                    isGroup: false
                });
                await chat.save();
            }
            
            // Notify sender about acceptance
            const senderSocket = userSockets.get(friendRequest.sender._id.toString());
            if (senderSocket) {
                io.to(senderSocket).emit('friend_request_accepted', {
                    requestId,
                    acceptorId: req.user._id,
                    acceptorName: req.user.name,
                    chatId: chat._id
                });
            }
        }
        
        // Notify receiver (current user) about action
        const receiverSocket = userSockets.get(req.user._id.toString());
        if (receiverSocket) {
            io.to(receiverSocket).emit('friend_request_processed', {
                requestId,
                action,
                status: friendRequest.status
            });
        }
        
        res.json({
            success: true,
            message: `Friend request ${action}ed successfully`,
            request: friendRequest
        });
        
    } catch (error) {
        console.error('Friend request action error:', error);
        res.status(500).json({ error: `Failed to ${action} friend request` });
    }
});

// Get Friends List
app.get('/api/friends', authenticate, async (req, res) => {
    try {
        const friendRequests = await FriendRequest.find({
            $or: [
                { sender: req.user._id, status: 'accepted' },
                { receiver: req.user._id, status: 'accepted' }
            ]
        })
        .populate('sender receiver', 'username name avatar status bio lastSeen')
        .sort({ updatedAt: -1 });
        
        const friends = friendRequests.map(request => 
            request.sender._id.equals(req.user._id) ? request.receiver : request.sender
        );
        
        // Sort by online status then name
        friends.sort((a, b) => {
            if (a.status === 'online' && b.status !== 'online') return -1;
            if (a.status !== 'online' && b.status === 'online') return 1;
            return a.name.localeCompare(b.name);
        });
        
        res.json(friends);
    } catch (error) {
        console.error('Get friends error:', error);
        res.status(500).json({ error: 'Failed to get friends list' });
    }
});

// Remove Friend
app.delete('/api/friends/:friendId', authenticate, async (req, res) => {
    try {
        const { friendId } = req.params;
        
        // Find and update the friend request
        const friendRequest = await FriendRequest.findOneAndUpdate({
            $or: [
                { sender: req.user._id, receiver: friendId, status: 'accepted' },
                { sender: friendId, receiver: req.user._id, status: 'accepted' }
            ]
        }, {
            status: 'cancelled'
        }, {
            new: true
        });
        
        if (!friendRequest) {
            return res.status(404).json({ error: 'Friend not found' });
        }
        
        // Delete the chat
        await Chat.findOneAndDelete({
            participants: { $all: [req.user._id, friendId] },
            isGroup: false
        });
        
        // Notify friend via socket
        const friendSocket = userSockets.get(friendId);
        if (friendSocket) {
            io.to(friendSocket).emit('friend_removed', {
                removedBy: req.user._id,
                removedByName: req.user.name
            });
        }
        
        res.json({
            success: true,
            message: 'Friend removed successfully'
        });
        
    } catch (error) {
        console.error('Remove friend error:', error);
        res.status(500).json({ error: 'Failed to remove friend' });
    }
});

// Chats
app.post('/api/chats', authenticate, async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'User ID is required' });
        }
        
        if (userId === req.user._id.toString()) {
            return res.status(400).json({ error: 'Cannot create chat with yourself' });
        }
        
        // Check if users are friends
        const areFriends = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: userId, status: 'accepted' },
                { sender: userId, receiver: req.user._id, status: 'accepted' }
            ]
        });
        
        if (!areFriends) {
            return res.status(403).json({ error: 'You can only chat with friends' });
        }
        
        // Check if blocked
        if (req.user.blockedUsers.includes(userId)) {
            return res.status(403).json({ error: 'You have blocked this user' });
        }
        
        const otherUser = await User.findById(userId);
        if (otherUser?.blockedUsers?.includes(req.user._id)) {
            return res.status(403).json({ error: 'This user has blocked you' });
        }
        
        // Check if chat already exists
        let chat = await Chat.findOne({
            participants: { $all: [req.user._id, userId] },
            isGroup: false
        }).populate('participants', 'username name avatar status');
        
        if (!chat) {
            // Create new chat
            chat = new Chat({
                participants: [req.user._id, userId],
                isGroup: false
            });
            
            await chat.save();
            await chat.populate('participants', 'username name avatar status');
        }
        
        res.json(chat);
        
    } catch (error) {
        console.error('Create chat error:', error);
        res.status(500).json({ error: 'Failed to create chat' });
    }
});

// Get User Chats
app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({
            participants: req.user._id,
            isGroup: false
        })
        .populate('participants', 'username name avatar status')
        .populate({
            path: 'lastMessage',
            populate: {
                path: 'sender',
                select: 'username name avatar'
            }
        })
        .sort({ updatedAt: -1 });
        
        // Calculate unread counts and add participant info
        const chatsWithDetails = await Promise.all(chats.map(async (chat) => {
            const otherParticipant = chat.participants.find(p => !p._id.equals(req.user._id));
            
            // Get unread count
            const unreadCount = await Message.countDocuments({
                chat: chat._id,
                sender: { $ne: req.user._id },
                'readBy.user': { $ne: req.user._id }
            });
            
            return {
                ...chat.toObject(),
                otherParticipant,
                unreadCount
            };
        }));
        
        res.json(chatsWithDetails);
    } catch (error) {
        console.error('Get chats error:', error);
        res.status(500).json({ error: 'Failed to get chats' });
    }
});

// Get Chat Messages
app.get('/api/chats/:chatId/messages', authenticate, async (req, res) => {
    try {
        const { chatId } = req.params;
        const { limit = 50, before } = req.query;
        
        // Verify user is participant
        const chat = await Chat.findById(chatId);
        if (!chat || !chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Not authorized to access this chat' });
        }
        
        // Build query
        const query = {
            chat: chatId,
            deletedFor: { $ne: req.user._id }
        };
        
        if (before) {
            query.createdAt = { $lt: new Date(before) };
        }
        
        const messages = await Message.find(query)
            .populate('sender', 'username name avatar')
            .populate('reactions.user', 'username name')
            .populate('replyTo', 'text sender')
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .then(messages => messages.reverse());
        
        res.json(messages);
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

// Send Message
app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text, replyTo, messageType = 'text' } = req.body;
        
        if (!chatId || !text || text.trim().length === 0) {
            return res.status(400).json({ error: 'Chat ID and message text are required' });
        }
        
        // Verify chat exists and user is participant
        const chat = await Chat.findById(chatId);
        if (!chat || !chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Not authorized to send messages in this chat' });
        }
        
        // Check if other user has blocked you
        const otherParticipantId = chat.participants.find(id => !id.equals(req.user._id));
        const otherUser = await User.findById(otherParticipantId);
        if (otherUser?.blockedUsers?.includes(req.user._id)) {
            return res.status(403).json({ error: 'You are blocked by this user' });
        }
        
        // Create message
        const message = new Message({
            chat: chatId,
            sender: req.user._id,
            text: text.trim(),
            messageType,
            replyTo,
            status: 'sent'
        });
        
        await message.save();
        
        // Update chat's last message
        chat.lastMessage = message._id;
        chat.updatedAt = new Date();
        
        // Increment unread count for other participants
        chat.participants.forEach(participantId => {
            if (!participantId.equals(req.user._id)) {
                const currentCount = chat.unreadCount.get(participantId.toString()) || 0;
                chat.unreadCount.set(participantId.toString(), currentCount + 1);
            }
        });
        
        await chat.save();
        
        // Populate message data for response
        await message.populate('sender', 'username name avatar');
        if (replyTo) {
            await message.populate('replyTo', 'text sender');
        }
        
        // Broadcast to chat participants
        const messageData = {
            message,
            chatId
        };
        
        chat.participants.forEach(participantId => {
            const participantSocket = userSockets.get(participantId.toString());
            if (participantSocket) {
                io.to(participantSocket).emit('new_message', messageData);
            }
        });
        
        res.json(message);
        
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Edit Message
app.put('/api/messages/:messageId', authenticate, async (req, res) => {
    try {
        const { messageId } = req.params;
        const { text } = req.body;
        
        if (!text || text.trim().length === 0) {
            return res.status(400).json({ error: 'Message text is required' });
        }
        
        const message = await Message.findById(messageId);
        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }
        
        // Check authorization
        if (!message.sender.equals(req.user._id)) {
            return res.status(403).json({ error: 'Not authorized to edit this message' });
        }
        
        // Check if chat allows editing
        const chat = await Chat.findById(message.chat);
        if (!chat.settings?.allowEditing) {
            return res.status(403).json({ error: 'Editing is not allowed in this chat' });
        }
        
        // Update message
        message.text = text.trim();
        message.edited = true;
        message.editedAt = new Date();
        await message.save();
        
        // Broadcast update
        const chatParticipants = chat.participants.map(p => p.toString());
        chatParticipants.forEach(participantId => {
            const participantSocket = userSockets.get(participantId);
            if (participantSocket) {
                io.to(participantSocket).emit('message_updated', {
                    messageId,
                    text: message.text,
                    edited: true,
                    editedAt: message.editedAt
                });
            }
        });
        
        res.json(message);
        
    } catch (error) {
        console.error('Edit message error:', error);
        res.status(500).json({ error: 'Failed to edit message' });
    }
});

// Delete Message
app.delete('/api/messages/:messageId', authenticate, async (req, res) => {
    try {
        const { messageId } = req.params;
        const { forEveryone } = req.body;
        
        const message = await Message.findById(messageId);
        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }
        
        const chat = await Chat.findById(message.chat);
        if (!chat || !chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        
        if (forEveryone) {
            // Delete for everyone (only sender can do this within time limit)
            if (!message.sender.equals(req.user._id)) {
                return res.status(403).json({ error: 'Only sender can delete for everyone' });
            }
            
            const timeDiff = Date.now() - message.createdAt;
            if (timeDiff > 5 * 60 * 1000) { // 5 minutes limit
                return res.status(400).json({ error: 'Can only delete for everyone within 5 minutes' });
            }
            
            await Message.findByIdAndDelete(messageId);
            
            // Broadcast deletion
            chat.participants.forEach(participantId => {
                const participantSocket = userSockets.get(participantId.toString());
                if (participantSocket) {
                    io.to(participantSocket).emit('message_deleted', {
                        messageId,
                        chatId: chat._id,
                        deletedForEveryone: true
                    });
                }
            });
        } else {
            // Delete for me only
            if (!message.deletedFor.includes(req.user._id)) {
                message.deletedFor.push(req.user._id);
                await message.save();
            }
        }
        
        res.json({
            success: true,
            message: 'Message deleted successfully'
        });
        
    } catch (error) {
        console.error('Delete message error:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// Block/Unblock User
app.post('/api/users/block/:userId', authenticate, async (req, res) => {
    try {
        const { userId } = req.params;
        const { action = 'block' } = req.body;
        
        if (userId === req.user._id.toString()) {
            return res.status(400).json({ error: 'Cannot block yourself' });
        }
        
        const userToBlock = await User.findById(userId);
        if (!userToBlock || !userToBlock.isActive) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (action === 'block') {
            // Add to blocked users list
            if (!req.user.blockedUsers.includes(userId)) {
                req.user.blockedUsers.push(userId);
                await req.user.save();
            }
            
            // Remove from friends
            await FriendRequest.findOneAndDelete({
                $or: [
                    { sender: req.user._id, receiver: userId },
                    { sender: userId, receiver: req.user._id }
                ],
                status: 'accepted'
            });
            
            // Update pending requests
            await FriendRequest.updateMany({
                $or: [
                    { sender: req.user._id, receiver: userId, status: 'pending' },
                    { sender: userId, receiver: req.user._id, status: 'pending' }
                ]
            }, {
                status: 'cancelled'
            });
            
            // Delete chat
            await Chat.findOneAndDelete({
                participants: { $all: [req.user._id, userId] },
                isGroup: false
            });
            
        } else if (action === 'unblock') {
            // Remove from blocked users list
            req.user.blockedUsers = req.user.blockedUsers.filter(id => 
                id.toString() !== userId
            );
            await req.user.save();
        }
        
        res.json({
            success: true,
            message: `User ${action}ed successfully`
        });
        
    } catch (error) {
        console.error('Block user error:', error);
        res.status(500).json({ error: `Failed to ${action} user` });
    }
});

// Get Blocked Users
app.get('/api/blocked-users', authenticate, async (req, res) => {
    try {
        const users = await User.find({
            _id: { $in: req.user.blockedUsers },
            isActive: true
        }).select('username name avatar email createdAt');
        
        res.json(users);
    } catch (error) {
        console.error('Get blocked users error:', error);
        res.status(500).json({ error: 'Failed to get blocked users' });
    }
});

// Get User Status
app.get('/api/users/:userId/status', authenticate, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const user = await User.findById(userId).select('status lastSeen');
        if (!user || !user.isActive) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            status: user.status,
            lastSeen: user.lastSeen,
            isOnline: user.status === 'online'
        });
    } catch (error) {
        console.error('Get user status error:', error);
        res.status(500).json({ error: 'Failed to get user status' });
    }
});

// Cleanup Old Data (optional endpoint for maintenance)
app.post('/api/cleanup', authenticate, async (req, res) => {
    try {
        // Only allow admins or implement proper authentication
        if (req.user.username !== 'admin') {
            return res.status(403).json({ error: 'Not authorized' });
        }
        
        // Delete messages older than 30 days
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        const deletedMessages = await Message.deleteMany({
            createdAt: { $lt: thirtyDaysAgo },
            messageType: 'text' // Don't delete media messages automatically
        });
        
        // Delete inactive chats (no messages for 60 days)
        const sixtyDaysAgo = new Date();
        sixtyDaysAgo.setDate(sixtyDaysAgo.getDate() - 60);
        
        const oldChats = await Chat.find({
            lastMessage: null,
            updatedAt: { $lt: sixtyDaysAgo }
        });
        
        let deletedChats = 0;
        for (const chat of oldChats) {
            await Message.deleteMany({ chat: chat._id });
            await chat.deleteOne();
            deletedChats++;
        }
        
        res.json({
            success: true,
            message: 'Cleanup completed',
            deletedMessages: deletedMessages.deletedCount,
            deletedChats
        });
        
    } catch (error) {
        console.error('Cleanup error:', error);
        res.status(500).json({ error: 'Cleanup failed' });
    }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: 'File upload error: ' + err.message });
    }
    
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 Handler
app.use('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`?? Server running on port ${PORT}`);
    console.log(`?? Static files: ${path.join(__dirname, 'public')}`);
    console.log(`?? Uploads: ${uploadDir}`);
    console.log(`?? WebSocket: ws://localhost:${PORT}`);
});