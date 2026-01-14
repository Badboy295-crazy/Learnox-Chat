const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

// 1. Socket Setup
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

// 2. Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/avatars/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

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
  avatar: { type: String, default: '' },
  status: { type: String, default: 'offline' },
  lastSeen: { type: Date, default: Date.now },
  chatBackground: { type: String, default: 'none' },
  createdAt: { type: Date, default: Date.now }
});

const chatSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: String,
  lastMessageTime: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat' },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: String,
  status: { type: String, default: 'sent' }, // sent, delivered, read
  edited: { type: Boolean, default: false },
  editedAt: { type: Date },
  deleted: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now }
});

const friendRequestSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, default: 'pending' }, // pending, accepted, rejected
  createdAt: { type: Date, default: Date.now }
});

const friendshipSchema = new mongoose.Schema({
  users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);
const Friendship = mongoose.model('Friendship', friendshipSchema);

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
    const user = new User({ 
      name, 
      email, 
      password: hashedPassword,
      status: 'online'
    });
    await user.save();
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET);
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
  } catch (e) { 
    console.error('Register error:', e);
    res.status(500).json({ error: 'Error creating user' }); 
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Update user status to online
    user.status = 'online';
    user.lastSeen = new Date();
    await user.save();
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET);
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
  } catch (e) { 
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error' }); 
  }
});

// User Profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

app.put('/api/user/profile', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    const { name, email, newPassword } = req.body;
    const user = await User.findById(req.user.id);
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Update avatar if provided
    if (req.file) {
      // Delete old avatar if exists
      if (user.avatar && user.avatar.includes('uploads/avatars/')) {
        const oldPath = path.join(__dirname, user.avatar);
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath);
        }
      }
      user.avatar = req.file.path;
    }
    
    // Update name and email
    if (name) user.name = name;
    if (email && email !== user.email) {
      const existing = await User.findOne({ email });
      if (existing) return res.status(400).json({ error: 'Email already exists' });
      user.email = email;
    }
    
    // Update password if provided
    if (newPassword) {
      user.password = await bcrypt.hash(newPassword, 10);
    }
    
    await user.save();
    
    res.json({ 
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Update User Status
app.post('/api/user/status', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    await User.findByIdAndUpdate(req.user.id, { 
      status, 
      lastSeen: new Date() 
    });
    
    // Notify all friends about status change
    const friendships = await Friendship.find({ users: req.user.id });
    for (const friendship of friendships) {
      const friendId = friendship.users.find(id => id.toString() !== req.user.id.toString());
      io.to(friendId.toString()).emit('user_status_changed', {
        userId: req.user.id,
        status: status
      });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Update status error:', error);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Search Users
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user.id } }).select('name email avatar status');
    res.json(users);
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// Get Friends
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    const friendships = await Friendship.find({ users: req.user.id })
      .populate('users', 'name email avatar status lastSeen');
    
    const friends = friendships.map(friendship => {
      const friend = friendship.users.find(user => user._id.toString() !== req.user.id.toString());
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
    console.error('Get friends error:', error);
    res.status(500).json({ error: 'Failed to get friends' });
  }
});

// Remove Friend
app.delete('/api/friends/:friendId', authenticateToken, async (req, res) => {
  try {
    const { friendId } = req.params;
    
    // Find and delete friendship
    const friendship = await Friendship.findOneAndDelete({
      users: { $all: [req.user.id, friendId] }
    });
    
    if (!friendship) {
      return res.status(404).json({ error: 'Friendship not found' });
    }
    
    // Delete the chat between users
    await Chat.findOneAndDelete({
      participants: { $all: [req.user.id, friendId] }
    });
    
    // Delete all messages in the chat
    const chat = await Chat.findOne({
      participants: { $all: [req.user.id, friendId] }
    });
    
    if (chat) {
      await Message.deleteMany({ chatId: chat._id });
    }
    
    // Notify the other user
    io.to(friendId).emit('friend_removed', { userId: req.user.id });
    
    res.json({ success: true, message: 'Friend removed successfully' });
  } catch (error) {
    console.error('Remove friend error:', error);
    res.status(500).json({ error: 'Failed to remove friend' });
  }
});

// Get Chats (Recent conversations)
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({ participants: req.user.id })
      .populate('participants', 'name email avatar status')
      .sort({ lastMessageTime: -1 });
    
    const chatList = await Promise.all(chats.map(async (chat) => {
      const otherUser = chat.participants.find(p => p._id.toString() !== req.user.id.toString());
      
      // Get unread messages count
      const unreadCount = await Message.countDocuments({
        chatId: chat._id,
        receiver: req.user.id,
        status: { $in: ['sent', 'delivered'] }
      });
      
      return {
        _id: chat._id,
        participants: chat.participants,
        otherUserId: otherUser?._id,
        otherUserName: otherUser?.name,
        lastMessage: chat.lastMessage,
        lastMessageTime: chat.lastMessageTime,
        unreadCount: unreadCount
      };
    }));
    
    res.json(chatList);
  } catch (error) {
    console.error('Get chats error:', error);
    res.status(500).json({ error: 'Failed to get chats' });
  }
});

// Get unread messages count for a specific user
app.get('/api/chats/unread/:userId', authenticateToken, async (req, res) => {
  try {
    const chat = await Chat.findOne({
      participants: { $all: [req.user.id, req.params.userId] }
    });
    
    if (!chat) {
      return res.json({ count: 0 });
    }
    
    const unreadCount = await Message.countDocuments({
      chatId: chat._id,
      receiver: req.user.id,
      status: { $in: ['sent', 'delivered'] }
    });
    
    res.json({ count: unreadCount });
  } catch (error) {
    console.error('Get unread count error:', error);
    res.status(500).json({ error: 'Failed to get unread count' });
  }
});

// Create/Open Chat
app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.body;
    
    // Check if chat already exists
    let chat = await Chat.findOne({
      participants: { $all: [req.user.id, userId] }
    }).populate('participants', 'name email avatar');
    
    if (!chat) {
      // Create new chat
      chat = new Chat({
        participants: [req.user.id, userId],
        lastMessage: null,
        lastMessageTime: null
      });
      await chat.save();
      await chat.populate('participants', 'name email avatar');
    }
    
    res.json({ 
      _id: chat._id,
      participants: chat.participants
    });
  } catch (error) {
    console.error('Create chat error:', error);
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

// Get Messages
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    // Verify user is a participant in this chat
    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.includes(req.user.id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const messages = await Message.find({ 
      chatId, 
      deleted: false 
    })
      .populate('sender', 'name avatar')
      .populate('receiver', 'name')
      .sort('timestamp');
    
    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

// Mark messages as read
app.post('/api/chats/:chatId/read', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    // Verify user is a participant in this chat
    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.includes(req.user.id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Find all messages sent to current user in this chat
    const messages = await Message.find({
      chatId: chatId,
      receiver: req.user.id,
      status: { $in: ['sent', 'delivered'] }
    });
    
    // Update status to read
    await Message.updateMany(
      {
        chatId: chatId,
        receiver: req.user.id,
        status: { $in: ['sent', 'delivered'] }
      },
      { status: 'read' }
    );
    
    // Notify sender that messages were read
    const senderId = chat.participants.find(id => id.toString() !== req.user.id.toString());
    messages.forEach(msg => {
      io.to(senderId.toString()).emit('message_read', {
        messageId: msg._id,
        chatId: chatId
      });
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Mark as read error:', error);
    res.status(500).json({ error: 'Failed to mark as read' });
  }
});

// Send Message
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId, text } = req.body;
    
    // Verify user is a participant in this chat
    const chat = await Chat.findById(chatId).populate('participants');
    if (!chat || !chat.participants.some(p => p._id.toString() === req.user.id.toString())) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Find receiver (other participant)
    const receiver = chat.participants.find(p => p._id.toString() !== req.user.id.toString());
    
    const message = new Message({
      chatId,
      sender: req.user.id,
      receiver: receiver._id,
      text,
      status: 'sent'
    });
    await message.save();
    
    // Update chat's last message
    chat.lastMessage = text;
    chat.lastMessageTime = new Date();
    await chat.save();
    
    // Populate sender and receiver details
    await message.populate('sender', 'name avatar');
    await message.populate('receiver', 'name');
    
    // Real-time send
    io.to(chatId).emit('new_message', message);
    io.to(receiver._id.toString()).emit('message_delivered', {
      messageId: message._id,
      chatId: chatId
    });
    
    // Send notification
    io.to(receiver._id.toString()).emit('new_message_notification', {
      chatId,
      message: message.text,
      senderName: message.sender.name
    });
    
    res.json(message);
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Edit Message
app.put('/api/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { text } = req.body;
    
    const message = await Message.findById(messageId)
      .populate('sender', 'name')
      .populate('receiver', 'name')
      .populate('chatId');
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Verify user is the sender
    if (message.sender._id.toString() !== req.user.id.toString()) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    // Update message
    message.text = text;
    message.edited = true;
    message.editedAt = new Date();
    await message.save();
    
    // Update chat's last message if this was the last message
    const chat = await Chat.findById(message.chatId);
    if (chat.lastMessage === message.text) {
      chat.lastMessage = text;
      await chat.save();
    }
    
    // Notify all participants
    io.to(message.chatId._id.toString()).emit('message_edited', message);
    
    res.json(message);
  } catch (error) {
    console.error('Edit message error:', error);
    res.status(500).json({ error: 'Failed to edit message' });
  }
});

// Delete Message (for everyone)
app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    
    const message = await Message.findById(messageId)
      .populate('sender', 'name')
      .populate('chatId');
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Verify user is the sender
    if (message.sender._id.toString() !== req.user.id.toString()) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    // Soft delete
    message.deleted = true;
    await message.save();
    
    // Notify all participants
    io.to(message.chatId._id.toString()).emit('message_deleted', {
      messageId: message._id,
      chatId: message.chatId._id
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// Friend Requests
app.get('/api/friend-requests/received', authenticateToken, async (req, res) => {
  try {
    const requests = await FriendRequest.find({
      receiver: req.user.id,
      status: 'pending'
    }).populate('sender', 'name email avatar');
    
    res.json(requests);
  } catch (error) {
    console.error('Get received requests error:', error);
    res.status(500).json({ error: 'Failed to get friend requests' });
  }
});

app.get('/api/friend-requests/sent', authenticateToken, async (req, res) => {
  try {
    const requests = await FriendRequest.find({
      sender: req.user.id,
      status: 'pending'
    }).populate('receiver', 'name email avatar');
    
    res.json(requests);
  } catch (error) {
    console.error('Get sent requests error:', error);
    res.status(500).json({ error: 'Failed to get sent requests' });
  }
});

app.post('/api/friend-requests/send', authenticateToken, async (req, res) => {
  try {
    const { receiverId } = req.body;
    
    // Check if already friends
    const existingFriendship = await Friendship.findOne({
      users: { $all: [req.user.id, receiverId] }
    });
    
    if (existingFriendship) {
      return res.status(400).json({ error: 'Already friends' });
    }
    
    // Check if request already exists
    const existingRequest = await FriendRequest.findOne({
      sender: req.user.id,
      receiver: receiverId,
      status: 'pending'
    });
    
    if (existingRequest) {
      return res.status(400).json({ error: 'Friend request already sent' });
    }
    
    // Create new friend request
    const request = new FriendRequest({
      sender: req.user.id,
      receiver: receiverId,
      status: 'pending'
    });
    await request.save();
    
    // Populate sender info
    await request.populate('sender', 'name email avatar');
    
    // Notify receiver in real-time
    io.to(receiverId).emit('friend_request_received', {
      _id: request._id,
      sender: request.sender,
      receiver: receiverId,
      senderName: request.sender.name
    });
    
    res.json({ 
      success: true, 
      message: "Friend request sent successfully",
      request: request
    });
  } catch (error) {
    console.error('Send friend request error:', error);
    res.status(500).json({ error: 'Failed to send friend request' });
  }
});

app.post('/api/friend-requests/:requestId/:action', authenticateToken, async (req, res) => {
  try {
    const { requestId, action } = req.params;
    
    if (!['accept', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }
    
    const request = await FriendRequest.findById(requestId)
      .populate('sender', 'name email avatar')
      .populate('receiver', 'name email avatar');
    
    if (!request) {
      return res.status(404).json({ error: 'Friend request not found' });
    }
    
    // Verify current user is the receiver
    if (request.receiver._id.toString() !== req.user.id.toString()) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    // Update request status
    request.status = action === 'accept' ? 'accepted' : 'rejected';
    await request.save();
    
    if (action === 'accept') {
      // Create friendship
      const friendship = new Friendship({
        users: [request.sender._id, request.receiver._id]
      });
      await friendship.save();
      
      // Create chat for the new friends
      const chat = new Chat({
        participants: [request.sender._id, request.receiver._id],
        lastMessage: null,
        lastMessageTime: null
      });
      await chat.save();
      
      // Send welcome message
      const welcomeMessage = new Message({
        chatId: chat._id,
        sender: request.receiver._id,
        receiver: request.sender._id,
        text: 'Hello! ??',
        status: 'sent'
      });
      await welcomeMessage.save();
      
      // Update chat's last message
      chat.lastMessage = 'Hello! ??';
      chat.lastMessageTime = new Date();
      await chat.save();
      
      // Notify sender in real-time
      io.to(request.sender._id.toString()).emit('friend_request_accepted', {
        acceptorId: request.receiver._id,
        acceptorName: request.receiver.name
      });
    }
    
    res.json({ 
      success: true, 
      message: `Friend request ${action}ed`,
      request: request
    });
  } catch (error) {
    console.error('Handle friend request error:', error);
    res.status(500).json({ error: `Failed to ${action} friend request` });
  }
});

// Socket Logic
io.on('connection', (socket) => {
  console.log('New client connected');
  
  socket.on('join_user', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined their room`);
  });
  
  socket.on('join_chat', (chatId) => {
    socket.join(chatId);
    console.log(`User joined chat ${chatId}`);
  });
  
  socket.on('update_status', async (data) => {
    const { userId, status } = data;
    await User.findByIdAndUpdate(userId, { 
      status, 
      lastSeen: new Date() 
    });
    
    // Notify friends about status change
    const friendships = await Friendship.find({ users: userId });
    for (const friendship of friendships) {
      const friendId = friendship.users.find(id => id.toString() !== userId.toString());
      io.to(friendId.toString()).emit('user_status_changed', {
        userId: userId,
        status: status
      });
    }
  });
  
  socket.on('typing', (data) => {
    const { chatId, userId } = data;
    socket.to(chatId).emit('typing', {
      chatId,
      userId
    });
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Serve Index
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));