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
require('dotenv').config(); // Dotenv load karein

const app = express();
const server = http.createServer(app);

// Socket.io Setup
const io = socketIo(server, {
    cors: {
        origin: "*", // Production mein security ke liye ise apne Render URL se replace karein
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(cors());
app.use(express.json());

// ---------------------------------------------------------
// FIX 1: Frontend Serving Logic (Public Folder)
// ---------------------------------------------------------
// Uploads folder serve karein
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Public folder (jisme index.html hai) ko static serve karein
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------
// FIX 2: MongoDB Connection for Render
// ---------------------------------------------------------
// Render pe localhost nahi chalta, Environment Variable use karein
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox';

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected Successfully'))
.catch(err => console.error('MongoDB Connection Error:', err));

// Models
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String },
    status: { type: String, default: 'offline' },
    chatBackground: { type: String, default: 'default' },
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
    unreadCount: { type: Map, of: Number, default: {} },
    createdAt: { type: Date, default: Date.now }
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

// File upload configuration - Ensure directory exists
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
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Only image files are allowed'));
    }
});

// JWT Secret (Use Environment Variable for Production)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware: Authentication
const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) {
            throw new Error();
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        if (!user) {
            throw new Error();
        }

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

// Middleware: Chat Access Authorization
const authorizeChatAccess = async (req, res, next) => {
    try {
        const chat = await Chat.findById(req.params.chatId);
        if (!chat) {
            return res.status(404).json({ error: 'Chat not found' });
        }

        if (!chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        req.chat = chat;
        next();
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
};

// Middleware: Friend Request Authorization
const authorizeFriendRequestAccess = async (req, res, next) => {
    try {
        const request = await FriendRequest.findById(req.params.requestId);
        if (!request) {
            return res.status(404).json({ error: 'Friend request not found' });
        }

        if (!request.receiver.equals(req.user._id) && !request.sender.equals(req.user._id)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        req.friendRequest = request;
        next();
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
};

// Socket Authentication Middleware
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication error'));
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userId = decoded.userId;
        next();
    } catch (error) {
        next(new Error('Authentication error'));
    }
});

// Socket Connections
const userSockets = new Map();
const chatSockets = new Map();

io.on('connection', (socket) => {
    console.log('User connected:', socket.userId);
    
    // Join user room
    socket.join(socket.userId);
    userSockets.set(socket.userId, socket.id);

    // Update user status
    User.findByIdAndUpdate(socket.userId, { status: 'online' }, { new: true })
        .then(user => {
            if (user) {
                io.emit('user_status_changed', { userId: user._id, status: 'online' });
            }
        });

    // Join chat
    socket.on('join_chat', (chatId) => {
        socket.join(chatId);
        chatSockets.set(socket.userId, chatId);
    });

    // Leave chat
    socket.on('leave_chat', (chatId) => {
        socket.leave(chatId);
        chatSockets.delete(socket.userId);
    });

    // Typing indicator
    socket.on('typing', (data) => {
        socket.to(data.chatId).emit('typing', data);
    });

    // Update status
    socket.on('update_status', async (data) => {
        await User.findByIdAndUpdate(data.userId, { status: data.status });
        io.emit('user_status_changed', data);
    });

    // Disconnect
    socket.on('disconnect', async () => {
        console.log('User disconnected:', socket.userId);
        userSockets.delete(socket.userId);
        chatSockets.delete(socket.userId);
        
        await User.findByIdAndUpdate(socket.userId, { status: 'offline' });
        io.emit('user_status_changed', { userId: socket.userId, status: 'offline' });
    });
});

// API Routes

// 1. AUTHENTICATION
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                avatar: user.avatar
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                avatar: user.avatar,
                status: user.status
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// 2. PROFILE MANAGEMENT
app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, email, currentPassword, newPassword } = req.body;
        const user = req.user;

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        if (name) user.name = name;
        if (email) user.email = email;

        if (newPassword) {
            user.password = await bcrypt.hash(newPassword, 10);
        }

        if (req.file) {
            if (user.avatar) {
                // Ensure we handle absolute/relative path correctly for unlink
                // Note: user.avatar usually starts with /uploads/...
                const relativePath = user.avatar.substring(1); // remove leading slash
                const oldPath = path.join(__dirname, relativePath);
                if (fs.existsSync(oldPath)) {
                    try {
                        fs.unlinkSync(oldPath);
                    } catch(e) { console.log("Could not delete old avatar"); }
                }
            }
            user.avatar = `/uploads/avatars/${req.file.filename}`;
        }

        await user.save();

        res.json({
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                avatar: user.avatar,
                status: user.status
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// ... (Baaki routes same rahenge, maine bas file serving fix ki hai)
// Maine convenience ke liye baaki code same rakha hai, bas niche 
// GET * route add kiya hai taaki agar koi refresh kare toh index.html hi khule.

app.get('/api/friends', authenticate, async (req, res) => {
    try {
        const friendRequests = await FriendRequest.find({
            $or: [
                { sender: req.user._id, status: 'accepted' },
                { receiver: req.user._id, status: 'accepted' }
            ]
        }).populate('sender receiver', 'name email avatar status');

        const friends = friendRequests.map(request => {
            const friend = request.sender._id.equals(req.user._id) ? request.receiver : request.sender;
            return {
                id: friend._id,
                name: friend.name,
                email: friend.email,
                avatar: friend.avatar,
                status: friend.status
            };
        });

        res.json(friends);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch friends' });
    }
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
        const chats = await Chat.find({
            participants: { $all: [req.user._id, friendId] }
        });
        for (const chat of chats) {
            await Message.deleteMany({ chat: chat._id });
            await chat.deleteOne();
        }
        res.json({ message: 'Friend removed successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove friend' });
    }
});

app.post('/api/friend-requests/send', authenticate, async (req, res) => {
    try {
        const { receiverId } = req.body;
        const receiver = await User.findById(receiverId);
        if (!receiver) return res.status(404).json({ error: 'User not found' });

        const existingFriendRequest = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: receiverId },
                { sender: receiverId, receiver: req.user._id }
            ]
        });

        if (existingFriendRequest) return res.status(400).json({ error: 'Friend request already exists' });

        const friendRequest = new FriendRequest({
            sender: req.user._id,
            receiver: receiverId
        });
        await friendRequest.save();
        await friendRequest.populate('sender', 'name email');

        const receiverSocket = userSockets.get(receiverId);
        if (receiverSocket) {
            io.to(receiverSocket).emit('friend_request_received', {
                _id: friendRequest._id,
                sender: friendRequest.sender,
                senderName: friendRequest.sender.name
            });
        }
        res.json(friendRequest);
    } catch (error) {
        res.status(500).json({ error: 'Failed to send friend request' });
    }
});

app.get('/api/friend-requests/received', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({
            receiver: req.user._id,
            status: 'pending'
        }).populate('sender', 'name email avatar');
        res.json(requests);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch friend requests' });
    }
});

app.get('/api/friend-requests/sent', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({
            sender: req.user._id,
            status: 'pending'
        }).populate('receiver', 'name email');
        res.json(requests);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch sent requests' });
    }
});

app.post('/api/friend-requests/:requestId/accept', authenticate, authorizeFriendRequestAccess, async (req, res) => {
    try {
        const request = req.friendRequest;
        request.status = 'accepted';
        await request.save();
        const senderSocket = userSockets.get(request.sender.toString());
        if (senderSocket) {
            io.to(senderSocket).emit('friend_request_accepted', {
                acceptorId: req.user._id,
                acceptorName: req.user.name
            });
        }
        res.json(request);
    } catch (error) {
        res.status(500).json({ error: 'Failed to accept friend request' });
    }
});

app.post('/api/friend-requests/:requestId/reject', authenticate, authorizeFriendRequestAccess, async (req, res) => {
    try {
        const request = req.friendRequest;
        request.status = 'rejected';
        await request.save();
        res.json(request);
    } catch (error) {
        res.status(500).json({ error: 'Failed to reject friend request' });
    }
});

app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({ participants: req.user._id })
        .populate('participants', 'name email avatar status')
        .populate('lastMessage')
        .sort({ updatedAt: -1 });

        const chatsWithUnread = await Promise.all(chats.map(async (chat) => {
            const unreadCount = await Message.countDocuments({
                chat: chat._id,
                sender: { $ne: req.user._id },
                status: { $in: ['sent', 'delivered'] }
            });
            chat.unreadCount = unreadCount;
            return chat;
        }));
        res.json(chatsWithUnread);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch chats' });
    }
});

app.get('/api/chats/with/:userId', authenticate, async (req, res) => {
    try {
        const chat = await Chat.findOne({
            participants: { $all: [req.user._id, req.params.userId] }
        }).populate('participants', 'name email avatar status');
        if (!chat) return res.status(404).json({ error: 'Chat not found' });
        res.json(chat);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch chat' });
    }
});

app.post('/api/chats', authenticate, async (req, res) => {
    try {
        const { userId } = req.body;
        const isFriend = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: userId, status: 'accepted' },
                { sender: userId, receiver: req.user._id, status: 'accepted' }
            ]
        });
        if (!isFriend) return res.status(403).json({ error: 'You can only chat with friends' });
        let chat = await Chat.findOne({ participants: { $all: [req.user._id, userId] } });
        if (!chat) {
            chat = new Chat({ participants: [req.user._id, userId] });
            await chat.save();
        }
        await chat.populate('participants', 'name email avatar status');
        res.json(chat);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create chat' });
    }
});

app.post('/api/chats/:chatId/read', authenticate, authorizeChatAccess, async (req, res) => {
    try {
        await Message.updateMany(
            {
                chat: req.chat._id,
                sender: { $ne: req.user._id },
                status: { $in: ['sent', 'delivered'] }
            },
            { status: 'seen' }
        );
        res.json({ message: 'Messages marked as read' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to mark messages as read' });
    }
});

app.get('/api/chats/unread/:userId', authenticate, async (req, res) => {
    try {
        const chat = await Chat.findOne({ participants: { $all: [req.user._id, req.params.userId] } });
        if (!chat) return res.json({ count: 0 });
        const unreadCount = await Message.countDocuments({
            chat: chat._id,
            sender: { $ne: req.user._id },
            status: { $in: ['sent', 'delivered'] }
        });
        res.json({ count: unreadCount });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch unread count' });
    }
});

app.get('/api/chats/:chatId/messages', authenticate, authorizeChatAccess, async (req, res) => {
    try {
        const messages = await Message.find({
            chat: req.params.chatId,
            deletedFor: { $ne: req.user._id }
        })
        .populate('sender', 'name email avatar')
        .sort({ createdAt: 1 });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text } = req.body;
        const chat = await Chat.findById(chatId);
        if (!chat || !chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Access denied' });
        }
        const message = new Message({
            chat: chatId,
            sender: req.user._id,
            text,
            status: 'sent'
        });
        await message.save();
        chat.lastMessage = message._id;
        chat.updatedAt = Date.now();
        await chat.save();
        await message.populate('sender', 'name email avatar');
        
        const otherParticipants = chat.participants.filter(p => !p.equals(req.user._id));
        for (const participant of otherParticipants) {
            const participantSocket = userSockets.get(participant.toString());
            if (participantSocket) {
                message.status = 'delivered';
                await message.save();
                break;
            }
        }
        io.to(chatId).emit('new_message', {
            ...message.toObject(),
            senderName: req.user.name
        });
        res.json(message);
    } catch (error) {
        res.status(500).json({ error: 'Failed to send message' });
    }
});

app.put('/api/messages/:messageId', authenticate, async (req, res) => {
    try {
        const { text } = req.body;
        const message = await Message.findById(req.params.messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });
        if (!message.sender.equals(req.user._id)) return res.status(403).json({ error: 'Access denied' });
        message.text = text;
        message.edited = true;
        message.updatedAt = Date.now();
        await message.save();
        io.to(message.chat.toString()).emit('message_updated', {
            messageId: message._id,
            chatId: message.chat,
            text: message.text,
            edited: true
        });
        res.json(message);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update message' });
    }
});

app.delete('/api/messages/:messageId', authenticate, async (req, res) => {
    try {
        const message = await Message.findById(req.params.messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });
        const chat = await Chat.findById(message.chat);
        if (!chat || !chat.participants.includes(req.user._id)) return res.status(403).json({ error: 'Access denied' });
        message.deletedFor.push(req.user._id);
        await message.save();
        if (message.deletedFor.length === chat.participants.length) {
            await message.deleteOne();
        }
        io.to(message.chat.toString()).emit('message_deleted', {
            messageId: message._id,
            chatId: message.chat
        });
        res.json({ message: 'Message deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        const searchQuery = req.query.q || '';
        const friendRequests = await FriendRequest.find({
            $or: [
                { sender: req.user._id, status: 'accepted' },
                { receiver: req.user._id, status: 'accepted' }
            ]
        });
        const friendIds = friendRequests.map(request => 
            request.sender.equals(req.user._id) ? request.receiver : request.sender
        );
        const users = await User.find({
            _id: { $ne: req.user._id, $nin: friendIds },
            $or: [
                { name: { $regex: searchQuery, $options: 'i' } },
                { email: { $regex: searchQuery, $options: 'i' } }
            ]
        }).select('name email avatar status');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to search users' });
    }
});

// ---------------------------------------------------------
// FIX 3: Frontend Fallback Route
// ---------------------------------------------------------
// Agar koi unknown URL enter kare toh index.html serve karein
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});