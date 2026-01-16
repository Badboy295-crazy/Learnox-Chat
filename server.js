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
    username: { type: String, unique: true, sparse: true }, // Added: username field
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String },
    status: { type: String, default: 'offline' }, // online, offline
    chatBackground: { type: String, default: 'default' },
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

// Token Verification (Added)
app.get('/api/verify-token', authenticate, async (req, res) => {
    try {
        res.json({ 
            valid: true, 
            user: { 
                id: req.user._id, 
                username: req.user.username,
                name: req.user.name, 
                email: req.user.email, 
                avatar: req.user.avatar, 
                status: req.user.status 
            } 
        });
    } catch (error) {
        res.status(401).json({ valid: false, error: 'Invalid token' });
    }
});

// Auth
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, username } = req.body; // Added username
        
        // Check if email exists
        if(await User.findOne({ email })) {
            return res.status(400).json({ error: 'User with this email already exists' });
        }
        
        // Check if username exists (if provided)
        if (username && await User.findOne({ username })) {
            return res.status(400).json({ error: 'Username already taken' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ 
            name, 
            email, 
            username, // Added
            password: hashedPassword 
        });
        await user.save();
        
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
        console.error(error);
        res.status(500).json({ error: 'Registration failed' }); 
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
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
        console.error(error);
        res.status(500).json({ error: 'Login failed' }); 
    }
});

// Profile
app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, username, currentPassword, newPassword } = req.body; // Added username
        const user = req.user;

        // Verify current password
        if (!(await bcrypt.compare(currentPassword, user.password))) {
            return res.status(401).json({ error: 'Current password incorrect' });
        }

        // Update fields
        if (name) user.name = name;
        
        // Update username if provided and different
        if (username && username !== user.username) {
            // Check if username is already taken
            const existingUser = await User.findOne({ username, _id: { $ne: user._id } });
            if (existingUser) {
                return res.status(400).json({ error: 'Username already taken' });
            }
            user.username = username;
        }
        
        // Update password if provided
        if (newPassword) user.password = await bcrypt.hash(newPassword, 10);
        
        // Update avatar if provided
        if (req.file) {
            // Delete old avatar if exists
            if (user.avatar && user.avatar.startsWith('/uploads')) {
                const oldPath = path.join(__dirname, user.avatar.substring(1));
                if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
            }
            user.avatar = `/uploads/avatars/${req.file.filename}`;
        }
        
        await user.save();
        
        // Return updated user
        res.json({ 
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
        console.error(error);
        res.status(500).json({ error: 'Profile update failed' }); 
    }
});

// View Other Profile
app.get('/api/users/:userId', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId)
            .select('username name email avatar status createdAt');
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Error fetching profile' }); 
    }
});

// Friends
app.get('/api/friends', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({
            $or: [ 
                { sender: req.user._id, status: 'accepted' }, 
                { receiver: req.user._id, status: 'accepted' } 
            ]
        }).populate('sender receiver', 'username name email avatar status');

        // Filter out blocked users
        const blockedIds = req.user.blockedUsers.map(id => id.toString());
        
        const friends = requests.map(reqData => {
            const friend = reqData.sender._id.equals(req.user._id) ? reqData.receiver : reqData.sender;
            return friend;
        }).filter(f => !blockedIds.includes(f._id.toString()));

        // Format response
        const formattedFriends = friends.map(f => ({
            id: f._id,
            username: f.username,
            name: f.name, 
            email: f.email, 
            avatar: f.avatar, 
            status: f.status
        }));
        
        res.json(formattedFriends);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Fetch friends failed' }); 
    }
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
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Block failed' }); 
    }
});

// Remove Friend
app.delete('/api/friends/:friendId', authenticate, async (req, res) => {
    try {
        const friendId = req.params.friendId;
        await FriendRequest.deleteMany({
            $or: [
                { sender: req.user._id, receiver: friendId },
                { sender: friendId, receiver: req.user._id }
            ]
        });
        res.json({ message: 'Friend removed' });
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Remove friend failed' }); 
    }
});

// Friend Requests
app.post('/api/friend-requests/send', authenticate, async (req, res) => {
    try {
        const { receiverId } = req.body;
        
        // Check if already friends
        const existingFriend = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: receiverId, status: 'accepted' },
                { sender: receiverId, receiver: req.user._id, status: 'accepted' }
            ]
        });
        if (existingFriend) return res.status(400).json({ error: 'Already friends' });

        // Check if pending request exists
        const existingRequest = await FriendRequest.findOne({
            $or: [
                { sender: req.user._id, receiver: receiverId, status: 'pending' },
                { sender: receiverId, receiver: req.user._id, status: 'pending' }
            ]
        });
        if (existingRequest) return res.status(400).json({ error: 'Request already exists' });

        // Check if blocked
        const receiver = await User.findById(receiverId);
        if (receiver && receiver.blockedUsers.includes(req.user._id)) {
            return res.status(403).json({ error: 'Cannot send request' });
        }
        
        const request = new FriendRequest({ 
            sender: req.user._id, 
            receiver: receiverId 
        });
        await request.save();
        
        // Populate sender info for response
        await request.populate('sender', 'username name email avatar');
        
        // Notify receiver via socket if online
        const sock = userSockets.get(receiverId);
        if (sock) {
            io.to(sock).emit('friend_request_received', { 
                _id: request._id, 
                sender: request.sender 
            });
        }
        
        res.json(request);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Request failed' }); 
    }
});

app.get('/api/friend-requests/received', authenticate, async (req, res) => {
    try {
        const requests = await FriendRequest.find({ 
            receiver: req.user._id, 
            status: 'pending' 
        }).populate('sender', 'username name email avatar');
        
        res.json(requests);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Fetch failed' }); 
    }
});

app.post('/api/friend-requests/:requestId/:action', authenticate, async (req, res) => {
    try {
        const { action } = req.params; // accept or reject
        const request = await FriendRequest.findById(req.params.requestId);
        
        if (!request) return res.status(404).json({ error: 'Request not found' });
        if (!request.receiver.equals(req.user._id)) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        
        if (action === 'accept') {
            request.status = 'accepted';
            await request.save();
            
            // Notify sender via socket
            const sock = userSockets.get(request.sender.toString());
            if (sock) {
                io.to(sock).emit('friend_request_accepted', { 
                    acceptorId: req.user._id,
                    acceptorName: req.user.name 
                });
            }
        } else if (action === 'reject') {
            request.status = 'rejected';
            await request.save();
        } else {
            return res.status(400).json({ error: 'Invalid action' });
        }
        
        res.json(request);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Action failed' }); 
    }
});

// Chats
app.get('/api/chats', authenticate, async (req, res) => {
    try {
        const chats = await Chat.find({ participants: req.user._id })
            .populate({
                path: 'participants',
                select: 'username name email avatar status'
            })
            .populate('lastMessage')
            .sort({ updatedAt: -1 });

        // Add unread count and other participant info
        const chatsWithData = await Promise.all(chats.map(async (chat) => {
            const unread = await Message.countDocuments({
                chat: chat._id, 
                sender: { $ne: req.user._id }, 
                status: { $in: ['sent', 'delivered'] }
            });
            
            // Find other participant
            const otherParticipant = chat.participants.find(
                p => !p._id.equals(req.user._id)
            );
            
            return { 
                ...chat.toObject(), 
                unreadCount: unread,
                otherParticipant: otherParticipant || chat.participants[0]
            };
        }));
        
        res.json(chatsWithData);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Fetch chats failed' }); 
    }
});

app.post('/api/chats', authenticate, async (req, res) => {
    try {
        const { userId } = req.body;
        
        // Check if already friends
        const isFriend = await FriendRequest.findOne({
            $or: [ 
                { sender: req.user._id, receiver: userId, status: 'accepted' }, 
                { sender: userId, receiver: req.user._id, status: 'accepted' } 
            ]
        });
        
        if (!isFriend) return res.status(403).json({ error: 'Must be friends to chat' });

        // Find or create chat
        let chat = await Chat.findOne({ 
            participants: { $all: [req.user._id, userId] } 
        });
        
        if (!chat) {
            chat = new Chat({ participants: [req.user._id, userId] });
            await chat.save();
        }
        
        await chat.populate({
            path: 'participants',
            select: 'username name email avatar status'
        });
        
        res.json(chat);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Create chat failed' }); 
    }
});

app.get('/api/chats/:chatId/messages', authenticate, authorizeChatAccess, async (req, res) => {
    try {
        const messages = await Message.find({ 
            chat: req.params.chatId, 
            deletedFor: { $ne: req.user._id } 
        })
        .populate('sender', 'username name email avatar')
        .sort({ createdAt: 1 });
        
        res.json(messages);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Fetch messages failed' }); 
    }
});

app.post('/api/messages', authenticate, async (req, res) => {
    try {
        const { chatId, text } = req.body;
        
        // Validate chat exists and user is participant
        const chat = await Chat.findById(chatId);
        if (!chat || !chat.participants.includes(req.user._id)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Check if blocked by other participant
        const otherId = chat.participants.find(p => !p.equals(req.user._id));
        const otherUser = await User.findById(otherId);
        if (otherUser && otherUser.blockedUsers.includes(req.user._id)) {
            return res.status(403).json({ error: 'You are blocked by this user' });
        }

        // Create message
        const message = new Message({ 
            chat: chatId, 
            sender: req.user._id, 
            text, 
            status: 'sent' 
        });
        await message.save();
        
        // Update chat last message
        chat.lastMessage = message._id;
        chat.updatedAt = Date.now();
        await chat.save();
        
        // Populate sender info
        await message.populate('sender', 'username name email avatar');

        // Emit socket event
        io.to(chatId).emit('new_message', message.toObject());
        
        res.json(message);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Send failed' }); 
    }
});

// Mark messages as read
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
        res.json({ success: true });
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Read failed' }); 
    }
});

// Edit message
app.put('/api/messages/:messageId', authenticate, async (req, res) => {
    try {
        const { text } = req.body;
        const message = await Message.findById(req.params.messageId);
        
        if (!message) return res.status(404).json({ error: 'Message not found' });
        if (!message.sender.equals(req.user._id)) return res.status(403).json({ error: 'Not authorized' });
        
        message.text = text;
        message.edited = true;
        message.updatedAt = Date.now();
        await message.save();
        
        // Emit update event
        io.to(message.chat.toString()).emit('message_updated', { 
            messageId: message._id, 
            chatId: message.chat, 
            text: message.text, 
            edited: true 
        });
        
        res.json(message);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Update failed' }); 
    }
});

// Delete message (soft delete)
app.delete('/api/messages/:messageId', authenticate, async (req, res) => {
    try {
        const message = await Message.findById(req.params.messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });
        
        // Add user to deletedFor array
        if (!message.deletedFor.includes(req.user._id)) {
            message.deletedFor.push(req.user._id);
            await message.save();
        }
        
        // Emit deletion event
        io.to(message.chat.toString()).emit('message_deleted', { 
            messageId: message._id, 
            chatId: message.chat 
        });
        
        res.json({ success: true });
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Delete failed' }); 
    }
});

// Search Users (updated to include username search)
app.get('/api/users/search', authenticate, async (req, res) => {
    try {
        const q = req.query.q || '';
        const users = await User.find({
            _id: { $ne: req.user._id },
            $or: [ 
                { name: { $regex: q, $options: 'i' } }, 
                { email: { $regex: q, $options: 'i' } },
                { username: { $regex: q, $options: 'i' } } // Added username search
            ]
        }).select('username name email avatar status createdAt');
        
        res.json(users);
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Search failed' }); 
    }
});

// Catch-all route for SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'new.html')); // Changed from index.html to new.html
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));