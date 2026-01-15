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

// --- DATABASE & MODELS ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/learnox_v2';
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Error:', err));

// User Model (Added Username)
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true }, // Unique ID
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String, default: '' },
    status: { type: String, default: 'offline' },
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

// Friend Request
const FriendRequestSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' }
});

// Chat Model (For Sorting)
const ChatSchema = new mongoose.Schema({
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
    updatedAt: { type: Date, default: Date.now } // Critical for sorting
});

// Message Model (Reactions & Status)
const MessageSchema = new mongoose.Schema({
    chat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat' },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: { type: String, required: true },
    status: { type: String, enum: ['sent', 'delivered', 'seen'], default: 'sent' },
    reactions: { type: Map, of: String, default: {} }, // UserID -> Emoji
    edited: { type: Boolean, default: false },
    deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Chat = mongoose.model('Chat', ChatSchema);
const Message = mongoose.model('Message', MessageSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);

// --- CONFIG ---
const JWT_SECRET = 'secret_key_123';
const uploadDir = path.join(__dirname, 'uploads/avatars');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
const upload = multer({ dest: uploadDir });

// --- MIDDLEWARE ---
const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error();
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = await User.findById(decoded.userId);
        if (!req.user) throw new Error();
        next();
    } catch { res.status(401).json({ error: 'Unauthorized' }); }
};

// --- SOCKET LOGIC ---
const userSockets = new Map(); // UserId -> SocketId

io.on('connection', (socket) => {
    socket.on('join_user', async (userId) => {
        socket.join(userId);
        socket.userId = userId;
        userSockets.set(userId, socket.id);
        
        await User.findByIdAndUpdate(userId, { status: 'online' });
        socket.broadcast.emit('user_status_changed', { userId, status: 'online' });

        // Deliver pending messages
        const pendingMsgs = await Message.find({ 
            sender: { $ne: userId }, 
            status: 'sent',
            chat: { $in: await getChatIdsForUser(userId) } 
        });

        for (let msg of pendingMsgs) {
            msg.status = 'delivered';
            await msg.save();
            io.to(userSockets.get(msg.sender.toString())).emit('msg_status_update', { msgId: msg._id, status: 'delivered' });
        }
    });

    socket.on('join_chat', (chatId) => socket.join(chatId));

    socket.on('typing', ({ chatId }) => socket.to(chatId).emit('typing', { chatId, userId: socket.userId }));
    socket.on('stop_typing', ({ chatId }) => socket.to(chatId).emit('stop_typing', { chatId, userId: socket.userId }));

    socket.on('mark_seen', async ({ chatId }) => {
        // Mark all messages in this chat sent by others as seen
        const msgs = await Message.find({ chat: chatId, sender: { $ne: socket.userId }, status: { $ne: 'seen' } });
        for (let msg of msgs) {
            msg.status = 'seen';
            await msg.save();
            const senderSocket = userSockets.get(msg.sender.toString());
            if (senderSocket) io.to(senderSocket).emit('msg_status_update', { msgId: msg._id, status: 'seen' });
        }
    });

    socket.on('disconnect', async () => {
        if (socket.userId) {
            userSockets.delete(socket.userId);
            await User.findByIdAndUpdate(socket.userId, { status: 'offline' });
            socket.broadcast.emit('user_status_changed', { userId: socket.userId, status: 'offline' });
        }
    });
});

async function getChatIdsForUser(userId) {
    const chats = await Chat.find({ participants: userId });
    return chats.map(c => c._id);
}

// --- API ROUTES ---

// Auth
app.post('/api/register', async (req, res) => {
    try {
        const { name, username, email, password } = req.body;
        // Validate Username
        if (!username || username.length < 3) return res.status(400).json({ error: 'Invalid username' });
        
        const hash = await bcrypt.hash(password, 10);
        const user = new User({ name, username, email, password: hash });
        await user.save();
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.json({ token, user });
    } catch (e) { res.status(400).json({ error: 'Username or Email exists' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) throw new Error();
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.json({ token, user });
    } catch { res.status(400).json({ error: 'Invalid credentials' }); }
});

// Profile (Update Avatar)
app.put('/api/profile', authenticate, upload.single('avatar'), async (req, res) => {
    try {
        const { name, newPassword } = req.body;
        if (name) req.user.name = name;
        if (newPassword) req.user.password = await bcrypt.hash(newPassword, 10);
        if (req.file) req.user.avatar = `/uploads/${req.file.filename}`; // Simplified path
        await req.user.save();
        res.json({ user: req.user });
    } catch (e) { res.status(500).json({ error: 'Error updating profile' }); }
});

// Search (By Username)
app.get('/api/users/search', authenticate, async (req, res) => {
    const q = req.query.q;
    const users = await User.find({ 
        username: { $regex: q, $options: 'i' }, 
        _id: { $ne: req.user._id } 
    }).select('name username avatar status');
    res.json(users);
});

// Friend Requests
app.get('/api/friends', authenticate, async (req, res) => {
    const friends = await FriendRequest.find({ 
        $or: [{sender: req.user._id, status: 'accepted'}, {receiver: req.user._id, status: 'accepted'}] 
    }).populate('sender receiver', 'name username avatar status');
    
    const list = friends.map(f => f.sender._id.equals(req.user._id) ? f.receiver : f.sender);
    res.json(list);
});

app.post('/api/friend-requests/send', authenticate, async (req, res) => {
    const { receiverId } = req.body;
    if (await FriendRequest.findOne({ $or: [{sender: req.user._id, receiver: receiverId}, {sender: receiverId, receiver: req.user._id}] })) 
        return res.status(400).json({ error: 'Request exists' });
    await new FriendRequest({ sender: req.user._id, receiver: receiverId }).save();
    res.json({ success: true });
});

app.get('/api/friend-requests/received', authenticate, async (req, res) => {
    const list = await FriendRequest.find({ receiver: req.user._id, status: 'pending' }).populate('sender', 'name username avatar');
    res.json(list);
});

app.post('/api/friend-requests/:id/:action', authenticate, async (req, res) => {
    const reqData = await FriendRequest.findById(req.params.id);
    if (!reqData) return res.status(404).json({error: 'Not found'});
    
    reqData.status = req.params.action === 'accept' ? 'accepted' : 'rejected';
    if(req.params.action === 'reject') await reqData.deleteOne();
    else await reqData.save();
    res.json({ success: true });
});

// Chats (Sorted)
app.get('/api/chats', authenticate, async (req, res) => {
    const chats = await Chat.find({ participants: req.user._id })
        .populate('participants', 'name username avatar status')
        .populate('lastMessage')
        .sort({ updatedAt: -1 }); // Real-time sorting
    res.json(chats);
});

app.post('/api/chats', authenticate, async (req, res) => {
    const { userId } = req.body;
    let chat = await Chat.findOne({ participants: { $all: [req.user._id, userId] } });
    if (!chat) {
        chat = new Chat({ participants: [req.user._id, userId] });
        await chat.save();
    }
    await chat.populate('participants', 'name username avatar');
    res.json(chat);
});

// Messages
app.get('/api/chats/:chatId/messages', authenticate, async (req, res) => {
    const msgs = await Message.find({ chat: req.params.chatId, deletedFor: { $ne: req.user._id } })
        .populate('sender', 'name username')
        .sort({ createdAt: 1 });
    res.json(msgs);
});

app.post('/api/messages', authenticate, async (req, res) => {
    const { chatId, text } = req.body;
    const msg = new Message({ chat: chatId, sender: req.user._id, text, status: 'sent' });
    await msg.save();
    
    // Update Chat Time for Sorting
    await Chat.findByIdAndUpdate(chatId, { lastMessage: msg._id, updatedAt: Date.now() });
    
    const populated = await msg.populate('sender', 'name username');
    
    // Broadcast to others (Socket.to prevents double message to sender)
    io.to(chatId).emit('new_message', populated); 
    
    res.json(populated);
});

// Message Actions (Edit/Delete/Reaction)
app.put('/api/messages/:id', authenticate, async (req, res) => {
    const { text, reaction } = req.body;
    const msg = await Message.findById(req.params.id);
    
    if (text && msg.sender.equals(req.user._id)) {
        msg.text = text;
        msg.edited = true;
    }
    if (reaction) {
        msg.reactions.set(req.user._id.toString(), reaction);
    }
    await msg.save();
    io.to(msg.chat.toString()).emit('message_updated', { 
        id: msg._id, text: msg.text, edited: msg.edited, reactions: msg.reactions 
    });
    res.json(msg);
});

app.delete('/api/messages/:id', authenticate, async (req, res) => {
    const msg = await Message.findById(req.params.id);
    if(msg.sender.equals(req.user._id)) {
        msg.deletedFor.push(req.user._id); // Soft delete or hard delete depending on req
        // For simplicity, let's just emit deleted
        io.to(msg.chat.toString()).emit('message_deleted', { id: msg._id, chatId: msg.chat });
        await msg.deleteOne(); // Hard delete for now
    }
    res.json({success: true});
});

server.listen(3000, () => console.log('Server running on port 3000'));