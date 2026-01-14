const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path'); // Path module add kiya hai

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*", // Kisi bhi website se allow karega
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '.'))); // Frontend files serve karne ke liye

// MongoDB Connection (Ab ye Secret Box se link lega)
const mongoURI = process.env.MONGO_URI; 
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.log('DB Error:', err));

// Secret Key for Login
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  status: { type: String, default: 'offline' },
  lastSeen: { type: Date, default: Date.now },
  theme: { type: String, default: 'purple' },
  chatBackground: { type: String, default: 'default' },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  chat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  status: { type: String, default: 'sent' },
  timestamp: { type: Date, default: Date.now }
});

const chatSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: String, default: '' },
  lastMessageTime: { type: Date, default: Date.now },
  unreadCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const friendRequestSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const friendSchema = new mongoose.Schema({
  user1: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  user2: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Chat = mongoose.model('Chat', chatSchema);
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);
const Friend = mongoose.model('Friend', friendSchema);

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });
    
    user.status = 'online';
    user.lastSeen = Date.now();
    await user.save();
    
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, status: user.status, theme: user.theme, chatBackground: user.chatBackground } });
  } catch (error) { res.status(500).json({ error: 'Server error' }); }
});

// Other API Routes (Profile, Friends, Chats - Same logic, just make sure to use JWT_SECRET)
app.get('/api/profile', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  const { name, password, theme, chatBackground } = req.body;
  const updates = {};
  if (name) updates.name = name;
  if (theme) updates.theme = theme;
  if (chatBackground) updates.chatBackground = chatBackground;
  if (password) updates.password = await bcrypt.hash(password, 10);
  
  const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true }).select('-password');
  res.json(user);
});

app.put('/api/users/status', authenticateToken, async (req, res) => {
  const { status } = req.body;
  await User.findByIdAndUpdate(req.user.id, { status, lastSeen: Date.now() });
  io.emit('user_status_changed', { userId: req.user.id, status: status });
  res.json({ success: true });
});

app.get('/api/friends', authenticateToken, async (req, res) => {
  const friendships = await Friend.find({ $or: [{ user1: req.user.id }, { user2: req.user.id }] }).populate('user1 user2');
  const friends = friendships.map(f => {
    const friend = f.user1._id.toString() === req.user.id ? f.user2 : f.user1;
    return { _id: friend._id, name: friend.name, email: friend.email, status: friend.status, lastSeen: friend.lastSeen };
  });
  res.json(friends);
});

app.get('/api/users/search', authenticateToken, async (req, res) => {
  const { q } = req.query;
  let query = { _id: { $ne: req.user.id } };
  if (q) query.$or = [{ name: { $regex: q, $options: 'i' } }, { email: { $regex: q, $options: 'i' } }];
  
  const users = await User.find(query).select('name email status lastSeen');
  const usersWithStatus = await Promise.all(users.map(async (user) => {
    const isFriend = await Friend.findOne({ $or: [{ user1: req.user.id, user2: user._id }, { user1: user._id, user2: req.user.id }] });
    const hasPendingRequest = await FriendRequest.findOne({ $or: [{ sender: req.user.id, receiver: user._id, status: 'pending' }, { sender: user._id, receiver: req.user.id, status: 'pending' }] });
    return { ...user.toObject(), isFriend: !!isFriend, hasPendingRequest: !!hasPendingRequest, requestStatus: hasPendingRequest ? (hasPendingRequest.sender.toString() === req.user.id ? 'sent' : 'received') : null };
  }));
  res.json(usersWithStatus);
});

app.get('/api/friend-requests', authenticateToken, async (req, res) => {
  const requests = await FriendRequest.find({ receiver: req.user.id, status: 'pending' }).populate('sender', 'name email');
  res.json(requests);
});

app.post('/api/friend-requests', authenticateToken, async (req, res) => {
  const { receiverId } = req.body;
  const existingFriend = await Friend.findOne({ $or: [{ user1: req.user.id, user2: receiverId }, { user1: receiverId, user2: req.user.id }] });
  if (existingFriend) return res.status(400).json({ error: 'Already friends' });
  
  const existingRequest = await FriendRequest.findOne({ $or: [{ sender: req.user.id, receiver: receiverId, status: 'pending' }, { sender: receiverId, receiver: req.user.id, status: 'pending' }] });
  if (existingRequest) return res.status(400).json({ error: 'Request exists' });
  
  const request = new FriendRequest({ sender: req.user.id, receiver: receiverId });
  await request.save();
  const populatedRequest = await FriendRequest.findById(request._id).populate('sender', 'name email');
  io.to(`user_${receiverId}`).emit('friend_request', { requestId: request._id, sender: populatedRequest.sender });
  res.json({ success: true, request });
});

app.put('/api/friend-requests/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { action } = req.body;
  const request = await FriendRequest.findOne({ _id: id, receiver: req.user.id, status: 'pending' });
  if (!request) return res.status(404).json({ error: 'Request not found' });
  
  if (action === 'accept') {
    const friend = new Friend({ user1: request.sender, user2: request.receiver });
    await friend.save();
    const chat = new Chat({ participants: [request.sender, request.receiver] });
    await chat.save();
    request.status = 'accepted';
    await request.save();
    io.to(`user_${request.sender}`).emit('friend_request_accepted', { requestId: request._id, receiver: { _id: req.user.id, name: req.user.name } });
  } else if (action === 'reject') {
    request.status = 'rejected';
    await request.save();
  }
  res.json({ success: true });
});

app.get('/api/chats', authenticateToken, async (req, res) => {
  const chats = await Chat.find({ participants: req.user.id }).populate('participants', 'name email status lastSeen');
  const chatsWithOtherUser = await Promise.all(chats.map(async (chat) => {
    const otherUser = chat.participants.find(p => p._id.toString() !== req.user.id);
    const lastMessage = await Message.findOne({ chat: chat._id }).sort({ timestamp: -1 }).limit(1);
    const unreadCount = await Message.countDocuments({ chat: chat._id, receiver: req.user.id, status: 'sent' });
    return { _id: chat._id, otherUser: otherUser || chat.participants[0], lastMessage: lastMessage ? lastMessage.text : '', lastMessageTime: lastMessage ? lastMessage.timestamp : chat.createdAt, unreadCount: unreadCount };
  }));
  res.json(chatsWithOtherUser);
});

app.post('/api/chats', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  const existingChat = await Chat.findOne({ participants: { $all: [req.user.id, userId] } });
  if (existingChat) return res.json(existingChat);
  const chat = new Chat({ participants: [req.user.id, userId] });
  await chat.save();
  res.status(201).json(chat);
});

app.get('/api/chats/:id/messages', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const chat = await Chat.findOne({ _id: id, participants: req.user.id });
  if (!chat) return res.status(403).json({ error: 'Access denied' });
  const messages = await Message.find({ chat: id }).populate('sender', 'name').sort({ timestamp: 1 });
  await Message.updateMany({ chat: id, receiver: req.user.id, status: 'sent' }, { status: 'delivered' });
  res.json(messages);
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  const { chatId, receiverId, text } = req.body;
  const chat = await Chat.findOne({ _id: chatId, participants: { $all: [req.user.id, receiverId] } });
  if (!chat) return res.status(403).json({ error: 'Invalid chat' });
  
  const message = new Message({ chat: chatId, sender: req.user.id, receiver: receiverId, text: text });
  await message.save();
  
  chat.lastMessage = text;
  chat.lastMessageTime = Date.now();
  chat.unreadCount += 1;
  await chat.save();
  
  const populatedMessage = await Message.findById(message._id).populate('sender', 'name');
  io.to(`chat_${chatId}`).emit('new_message', populatedMessage);
  io.to(`user_${receiverId}`).emit('new_message_notification', { chatId: chatId, message: populatedMessage });
  res.status(201).json(populatedMessage);
});

// Socket.io
io.on('connection', (socket) => {
  console.log('New client connected');
  socket.on('join_user', (userId) => { socket.join(`user_${userId}`); });
  socket.on('join_chat', (chatId) => { socket.join(`chat_${chatId}`); });
  socket.on('typing', (data) => { socket.to(`chat_${data.chatId}`).emit('typing_status', data); });
  socket.on('disconnect', () => { console.log('Client disconnected'); });
});

// Serve frontend in production
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});