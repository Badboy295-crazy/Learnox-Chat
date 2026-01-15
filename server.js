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

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/learnox', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

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

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/avatars/');
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

// JWT Secret
const JWT_SECRET = 'your-secret-key-change-in-production';

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

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        // Generate token
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
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate token
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

        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Update user data
        if (name) user.name = name;
        if (email) user.email = email;

        // Update password if provided
        if (newPassword) {
            user.password = await bcrypt.hash(newPassword, 10);
        }

        // Update avatar if uploaded
        if (req.file) {
            // Delete old avatar if exists
            if (user.avatar) {
                const oldPath = path.join(__dirname, user.avatar);
                if (fs.existsSync(oldPath)) {
                    fs.unlinkSync(oldPath);
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
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// 3. FRIENDS MANAGEMENT
app.get('/api/friends', authenticate, async (req, res) => {
    try {
        // Find accepted friend requests
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

        // Remove friend requests
        await FriendRequest.deleteMany({
            $or: [
                { sender: req.user._id, receiver: friendId },
                { sender: friendId, receiver: req.user._id }
            ]
        });

        // Remove chats
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

// 4. FRIEND REQUESTS
app.post('/api/friend-requests/send', authenticate, async (req, res) => {
    try {
        const { receiverId } = req.body;

        // Check if receiver exists
        const receiver = await User.findById(receiverId);
        if (!receiver) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if already friends
        const existingFriendRequest = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: receiverId },
                { sender: receiverId, receiver: req.user._id }
            ]
        });

        if (existingFriendRequest) {
            return res.status(400).json({ error: 'Friend request already exists' });
        }

        // Create friend request
        const friendRequest = new FriendRequest({
            sender: req.user._id,
            receiver: receiverId
        });

        await friendRequest.save();

        // Populate sender info for socket
        await friendRequest.populate('sender', 'name email');

        // Notify receiver via socket
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

        // Notify sender via socket
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

// 5. CHAT MANAGEMENT
app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({
            participants: req.user._id
        })
        .populate('participants', 'name email avatar status')
        .populate('lastMessage')
        .sort({ updatedAt: -1 });

        // Calculate unread counts
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

        if (!chat) {
            return res.status(404).json({ error: 'Chat not found' });
        }

        res.json(chat);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch chat' });
    }
});

app.post('/api/chats', authenticate, async (req, res) => {
    try {
        const { userId } = req.body;

        // Check if users are friends
        const isFriend = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: userId, status: 'accepted' },
                { sender: userId, receiver: req.user._id, status: 'accepted' }
            ]
        });

        if (!isFriend) {
            return res.status(403).json({ error: 'You can only chat with friends' });
        }

        // Check if chat already exists
        let chat = await Chat.findOne({
            participants: { $all: [req.user._id, userId] }
        });

        if (!chat) {
            // Create new chat
            chat = new Chat({
                participants: [req.user._id, userId]
            });
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
        const chat = req.chat;

        // Update message status to seen
        await Message.updateMany(
            {
                chat: chat._id,
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
        const chat = await Chat.findOne({
            participants: { $all: [req.user._id, req.params.userId] }
        });

        if (!chat) {
            return res.json({ count: 0 });
        }

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

// 6. MESSAGES
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

        // Verify chat access
        const chat = await Chat.findById(chatId);
        if (!chat || !chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Create message
        const message = new Message({
            chat: chatId,
            sender: req.user._id,
            text,
            status: 'sent'
        });

        await message.save();

        // Update chat's last message
        chat.lastMessage = message._id;
        chat.updatedAt = Date.now();
        await chat.save();

        // Populate sender info
        await message.populate('sender', 'name email avatar');

        // Update message status to delivered for other participants
        const otherParticipants = chat.participants.filter(p => !p.equals(req.user._id));
        for (const participant of otherParticipants) {
            const participantSocket = userSockets.get(participant.toString());
            if (participantSocket) {
                message.status = 'delivered';
                await message.save();
                break;
            }
        }

        // Emit to chat room
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
        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }

        // Check ownership
        if (!message.sender.equals(req.user._id)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        message.text = text;
        message.edited = true;
        message.updatedAt = Date.now();
        await message.save();

        // Emit update
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
        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }

        // Check ownership or chat participation
        const chat = await Chat.findById(message.chat);
        if (!chat || !chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Add user to deletedFor array
        message.deletedFor.push(req.user._id);
        await message.save();

        // If all participants have deleted, remove message
        if (message.deletedFor.length === chat.participants.length) {
            await message.deleteOne();
        }

        // Emit deletion
        io.to(message.chat.toString()).emit('message_deleted', {
            messageId: message._id,
            chatId: message.chat
        });

        res.json({ message: 'Message deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// 7. USER SEARCH
app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        const searchQuery = req.query.q || '';
        
        // Find users who are not friends
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

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
    app.use(express.static('client/build'));
    app.get('*', (req, res) => {
        res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
    });
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`API available at http://localhost:${PORT}/api`);
});