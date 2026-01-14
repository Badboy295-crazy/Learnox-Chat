const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);

// 1. Socket Setup
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

// 2. Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '.'))); // HTML files serve karne ke liye

// 3. Database Connection
const mongoURI = process.env.MONGO_URI; 
if (!mongoURI) {
    console.error("FATAL ERROR: MONGO_URI is not defined.");
}
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Atlas Connected'))
  .catch(err => console.log('DB Error:', err));

const JWT_SECRET = process.env.JWT_SECRET || 'secretKey123';

// 4. Database Models (Schemas)
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  chatId: String, // String ID for simple chat linking
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: String,
  timestamp: { type: Date, default: Date.now }
});

const friendRequestSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, default: 'pending' } // pending, accepted
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);

// 5. Auth Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- ROUTES ---

// Auth
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already exists' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) { res.status(500).json({ error: 'Error creating user' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id }, JWT_SECRET);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// Search Users
app.get('/api/users/search', authenticateToken, async (req, res) => {
  // Return all users except self (Simplified for beginners)
  const users = await User.find({ _id: { $ne: req.user.id } }).select('name email');
  res.json(users);
});

// Friends Logic (Simplified: Search -> Click -> Auto Friend for this demo)
// Note: Proper friend request logic is complex, for this easy version, 
// we will treat the "Search" list as potential contacts.
app.get('/api/friends', authenticateToken, async (req, res) => {
    // For now, return all users so you can chat with anyone
    // In a real app, this would query the FriendRequest table for 'accepted' status
    const users = await User.find({ _id: { $ne: req.user.id } }).select('name email');
    res.json(users);
});

// Get Chats (Recent conversations)
app.get('/api/chats', authenticateToken, async (req, res) => {
  // Logic to find users you have messaged
  // Returning all users for simplicity to ensure UI is populated
  const users = await User.find({ _id: { $ne: req.user.id } }).select('name email');
  const chatList = users.map(u => ({
      _id: getChatId(req.user.id, u._id.toString()), // Unique Chat ID
      userId: u._id,
      name: u.name,
      lastMessage: "Click to chat"
  }));
  res.json(chatList);
});

// Create/Open Chat
app.post('/api/chats', authenticateToken, async (req, res) => {
    const { userId } = req.body;
    const chatId = getChatId(req.user.id, userId);
    res.json({ _id: chatId });
});

// Get Messages
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  const { chatId } = req.params;
  const messages = await Message.find({ chatId }).populate('sender', 'name').sort('timestamp');
  res.json(messages);
});

// Send Message
app.post('/api/messages', authenticateToken, async (req, res) => {
  const { chatId, text } = req.body;
  const message = new Message({
    chatId,
    sender: req.user.id,
    text
  });
  await message.save();
  
  // Populate sender details for the frontend
  await message.populate('sender', 'name');
  
  // Real-time send
  io.to(chatId).emit('new_message', message);
  res.json(message);
});

// Send Friend Request (Stub for UI compatibility)
app.post('/api/friend-requests', authenticateToken, async (req, res) => {
    res.json({ success: true, message: "Request Sent" });
});

// Helper: Generate consistent Chat ID between two users
function getChatId(user1, user2) {
    return [user1, user2].sort().join('_');
}

// Socket Logic
io.on('connection', (socket) => {
  socket.on('join_user', (userId) => {
    socket.join(userId);
  });
  
  socket.on('join_chat', (chatId) => {
    socket.join(chatId);
  });
  
  socket.on('disconnect', () => {
    // Cleanup if needed
  });
});

// Serve Index
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));