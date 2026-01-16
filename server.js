// server.js - Complete Messaging Platform Backend
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// Initialize Express
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
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Create public/uploads directory if it doesn't exist
if (!fs.existsSync('public/uploads')) {
  fs.mkdirSync('public/uploads', { recursive: true });
}

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp4|avi|mov|pdf|doc|docx|txt/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('File type not allowed'));
    }
  }
});

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/messaging_platform', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('? MongoDB Connected');
}).catch(err => {
  console.error('? MongoDB Connection Error:', err);
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  // Authentication
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  phone: { type: String, unique: true, sparse: true },
  password: { type: String, required: true },
  
  // Profile
  profilePic: { type: String, default: '/default-avatar.png' },
  bio: { type: String, default: '' },
  status: { 
    text: { type: String, default: 'Hey there! I am using ChatApp' },
    expiresAt: Date 
  },
  
  // Settings
  settings: {
    theme: { type: String, enum: ['light', 'dark', 'auto'], default: 'auto' },
    language: { type: String, default: 'en' },
    notifications: {
      sounds: { type: Boolean, default: true },
      desktop: { type: Boolean, default: true }
    }
  },
  
  // Privacy
  privacy: {
    lastSeen: { type: String, enum: ['everyone', 'contacts', 'nobody'], default: 'contacts' },
    profilePic: { type: String, enum: ['everyone', 'contacts', 'nobody'], default: 'everyone' },
    readReceipts: { type: Boolean, default: true },
    onlineStatus: { type: Boolean, default: true }
  },
  
  // Security
  twoFactorEnabled: { type: Boolean, default: false },
  blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  activeSessions: [{
    token: String,
    deviceInfo: Object,
    lastActivity: Date
  }],
  
  // Social
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  friendRequests: [{
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
  }],
  
  // Timestamps
  lastSeen: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  // Chat reference
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  
  // Content
  type: { 
    type: String, 
    enum: ['text', 'image', 'video', 'audio', 'document', 'location', 'contact', 'sticker'],
    default: 'text'
  },
  content: String,
  fileUrl: String,
  fileName: String,
  fileSize: Number,
  
  // Reactions
  reactions: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    emoji: String,
    createdAt: { type: Date, default: Date.now }
  }],
  
  // Status tracking
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  deliveredTo: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  
  // Deletion
  deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  deletedForEveryone: { type: Boolean, default: false },
  
  // Reply
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  forwarded: { type: Boolean, default: false },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const chatSchema = new mongoose.Schema({
  // Type of chat
  type: { type: String, enum: ['private', 'group'], required: true },
  
  // Participants
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
  
  // Group info
  name: String,
  description: String,
  groupPic: String,
  
  // Admin controls
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  
  // Settings
  settings: {
    sendMessages: { type: String, enum: ['all', 'admins'], default: 'all' },
    addParticipants: { type: String, enum: ['all', 'admins'], default: 'admins' }
  },
  
  // Last activity
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  pinnedMessages: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Message' }],
  
  // Unread counts
  unreadCounts: {
    type: Map,
    of: Number,
    default: {}
  },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const storySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['text', 'image', 'video'], required: true },
  content: String,
  backgroundColor: String,
  textColor: String,
  views: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  reactions: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    emoji: String,
    createdAt: { type: Date, default: Date.now }
  }],
  expiresAt: { type: Date, default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) }, // 24 hours
  createdAt: { type: Date, default: Date.now }
});

// Create Models
const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Chat = mongoose.model('Chat', chatSchema);
const Story = mongoose.model('Story', storySchema);

// JWT Secret (In production, use environment variable)
const JWT_SECRET = 'your-super-secret-jwt-key-change-this-in-production';

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Store online users
const onlineUsers = new Map();

// API Routes

// 1. AUTHENTICATION ROUTES
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, phone } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }, { phone }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      username,
      email,
      phone,
      password: hashedPassword,
      profilePic: `/default-avatar.png`
    });
    
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profilePic: user.profilePic,
        bio: user.bio,
        status: user.status
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
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
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last seen
    user.lastSeen = new Date();
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profilePic: user.profilePic,
        bio: user.bio,
        status: user.status,
        settings: user.settings
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// 2. USER PROFILE ROUTES
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('-password -activeSessions');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

app.put('/api/user/profile', authenticateToken, upload.single('profilePic'), async (req, res) => {
  try {
    const { username, bio, status } = req.body;
    const updates = {};
    
    if (username) updates.username = username;
    if (bio) updates.bio = bio;
    if (status) updates.status = { text: status, expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) };
    
    if (req.file) {
      updates.profilePic = `/uploads/${req.file.filename}`;
    }
    
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      updates,
      { new: true }
    ).select('-password -activeSessions');
    
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// 3. CHAT ROUTES
app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { participantId } = req.body;
    
    // Check if chat already exists
    let chat = await Chat.findOne({
      type: 'private',
      participants: { $all: [req.user.userId, participantId], $size: 2 }
    });
    
    if (chat) {
      return res.json({ success: true, chat });
    }
    
    // Create new chat
    chat = new Chat({
      type: 'private',
      participants: [req.user.userId, participantId],
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    await chat.save();
    res.status(201).json({ success: true, chat });
  } catch (error) {
    console.error('Create chat error:', error);
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

app.post('/api/chats/group', authenticateToken, async (req, res) => {
  try {
    const { name, description, participants } = req.body;
    
    const chat = new Chat({
      type: 'group',
      name,
      description,
      participants: [...participants, req.user.userId],
      admins: [req.user.userId],
      createdBy: req.user.userId,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    await chat.save();
    res.status(201).json({ success: true, chat });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create group' });
  }
});

app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({
      participants: req.user.userId
    })
    .populate('participants', 'username profilePic status')
    .populate('lastMessage')
    .sort({ updatedAt: -1 });
    
    res.json({ success: true, chats });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get chats' });
  }
});

// 4. MESSAGE ROUTES
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { page = 1, limit = 50 } = req.query;
    
    const messages = await Message.find({ 
      chatId,
      deletedFor: { $ne: req.user.userId }
    })
    .populate('sender', 'username profilePic')
    .populate('replyTo')
    .sort({ createdAt: -1 })
    .skip((page - 1) * limit)
    .limit(parseInt(limit))
    .exec();
    
    res.json({ 
      success: true, 
      messages: messages.reverse(),
      page,
      limit,
      total: await Message.countDocuments({ chatId })
    });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

app.post('/api/messages', authenticateToken, upload.array('files', 10), async (req, res) => {
  try {
    const { chatId, content, type, replyTo } = req.body;
    
    // Check if user is participant
    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    let fileUrl = null;
    let fileName = null;
    let fileSize = null;
    
    if (req.files && req.files.length > 0) {
      fileUrl = `/uploads/${req.files[0].filename}`;
      fileName = req.files[0].originalname;
      fileSize = req.files[0].size;
    }
    
    const message = new Message({
      chatId,
      sender: req.user.userId,
      type: type || (fileUrl ? 'image' : 'text'),
      content,
      fileUrl,
      fileName,
      fileSize,
      replyTo,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    await message.save();
    
    // Update chat last message
    chat.lastMessage = message._id;
    chat.updatedAt = new Date();
    
    // Increment unread count for all participants except sender
    chat.participants.forEach(participantId => {
      if (participantId.toString() !== req.user.userId.toString()) {
        const currentCount = chat.unreadCounts.get(participantId.toString()) || 0;
        chat.unreadCounts.set(participantId.toString(), currentCount + 1);
      }
    });
    
    await chat.save();
    
    // Populate message for real-time
    const populatedMessage = await Message.findById(message._id)
      .populate('sender', 'username profilePic')
      .populate('replyTo');
    
    res.status(201).json({ success: true, message: populatedMessage });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.put('/api/messages/:messageId/read', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Add user to readBy array if not already
    if (!message.readBy.includes(req.user.userId)) {
      message.readBy.push(req.user.userId);
      await message.save();
    }
    
    // Reset unread count for this chat
    const chat = await Chat.findById(message.chatId);
    if (chat) {
      chat.unreadCounts.set(req.user.userId.toString(), 0);
      await chat.save();
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark as read' });
  }
});

app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { forEveryone } = req.body;
    
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    if (message.sender.toString() !== req.user.userId.toString()) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    if (forEveryone) {
      message.deletedForEveryone = true;
      await message.save();
    } else {
      message.deletedFor.push(req.user.userId);
      await message.save();
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// 5. FRIEND ROUTES
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .populate('friends', 'username profilePic status lastSeen')
      .populate('friendRequests.from', 'username profilePic');
    
    res.json({
      success: true,
      friends: user.friends,
      friendRequests: user.friendRequests
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get friends' });
  }
});

app.post('/api/friends/request', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.body;
    
    const targetUser = await User.findById(userId);
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if already friends
    if (targetUser.friends.includes(req.user.userId)) {
      return res.status(400).json({ error: 'Already friends' });
    }
    
    // Check if request already exists
    const existingRequest = targetUser.friendRequests.find(
      req => req.from.toString() === req.user.userId.toString()
    );
    
    if (existingRequest) {
      return res.status(400).json({ error: 'Friend request already sent' });
    }
    
    // Add friend request
    targetUser.friendRequests.push({
      from: req.user.userId,
      status: 'pending'
    });
    
    await targetUser.save();
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send friend request' });
  }
});

app.put('/api/friends/request/:requestId', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;
    const { action } = req.body; // 'accept' or 'reject'
    
    const user = await User.findById(req.user.userId);
    const request = user.friendRequests.id(requestId);
    
    if (!request) {
      return res.status(404).json({ error: 'Friend request not found' });
    }
    
    if (action === 'accept') {
      // Add to friends list
      user.friends.push(request.from);
      
      const friendUser = await User.findById(request.from);
      friendUser.friends.push(req.user.userId);
      await friendUser.save();
    }
    
    // Remove the request
    user.friendRequests.pull(requestId);
    await user.save();
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process friend request' });
  }
});

// 6. SEARCH ROUTES
app.get('/api/search/users', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    
    const users = await User.find({
      $or: [
        { username: { $regex: query, $options: 'i' } },
        { email: { $regex: query, $options: 'i' } }
      ],
      _id: { $ne: req.user.userId }
    })
    .select('username profilePic status bio')
    .limit(20);
    
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// 7. STORY ROUTES
app.post('/api/stories', authenticateToken, upload.single('media'), async (req, res) => {
  try {
    const { type, content, backgroundColor, textColor } = req.body;
    let mediaUrl = null;
    
    if (req.file) {
      mediaUrl = `/uploads/${req.file.filename}`;
    }
    
    const story = new Story({
      user: req.user.userId,
      type,
      content: mediaUrl || content,
      backgroundColor,
      textColor,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
    });
    
    await story.save();
    
    // Populate user info
    await story.populate('user', 'username profilePic');
    
    res.status(201).json({ success: true, story });
  } catch (error) {
    console.error('Create story error:', error);
    res.status(500).json({ error: 'Failed to create story' });
  }
});

app.get('/api/stories', authenticateToken, async (req, res) => {
  try {
    const friends = await User.findById(req.user.userId).select('friends');
    
    const stories = await Story.find({
      $or: [
        { user: req.user.userId },
        { user: { $in: friends.friends } }
      ],
      expiresAt: { $gt: new Date() }
    })
    .populate('user', 'username profilePic')
    .sort({ createdAt: -1 });
    
    // Group stories by user
    const groupedStories = {};
    stories.forEach(story => {
      const userId = story.user._id.toString();
      if (!groupedStories[userId]) {
        groupedStories[userId] = {
          user: story.user,
          stories: []
        };
      }
      groupedStories[userId].stories.push(story);
    });
    
    res.json({ 
      success: true, 
      stories: Object.values(groupedStories) 
    });
  } catch (error) {
    console.error('Get stories error:', error);
    res.status(500).json({ error: 'Failed to get stories' });
  }
});

app.post('/api/stories/:storyId/view', authenticateToken, async (req, res) => {
  try {
    const { storyId } = req.params;
    
    const story = await Story.findById(storyId);
    if (!story) {
      return res.status(404).json({ error: 'Story not found' });
    }
    
    // Add view if not already viewed
    if (!story.views.includes(req.user.userId)) {
      story.views.push(req.user.userId);
      await story.save();
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record view' });
  }
});

// 8. SETTINGS ROUTES
app.put('/api/user/settings', authenticateToken, async (req, res) => {
  try {
    const { settings, privacy } = req.body;
    const updates = {};
    
    if (settings) updates.settings = settings;
    if (privacy) updates.privacy = privacy;
    
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      updates,
      { new: true }
    ).select('-password -activeSessions');
    
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// 9. BLOCK USER
app.post('/api/users/:userId/block', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(req.user.userId);
    if (!user.blockedUsers.includes(userId)) {
      user.blockedUsers.push(userId);
      await user.save();
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to block user' });
  }
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.io Connection Handling
io.on('connection', (socket) => {
  console.log('?? New connection:', socket.id);
  
  // User joins with their user ID
  socket.on('join', async (userId) => {
    if (!userId) return;
    
    socket.userId = userId;
    socket.join(`user:${userId}`);
    onlineUsers.set(userId, socket.id);
    
    // Update user status to online
    await User.findByIdAndUpdate(userId, { 
      lastSeen: new Date()
    });
    
    // Notify friends that user is online
    const user = await User.findById(userId).populate('friends');
    user.friends.forEach(friend => {
      socket.to(`user:${friend._id}`).emit('user_status', {
        userId,
        status: 'online'
      });
    });
    
    console.log(`?? User ${userId} connected. Online users: ${onlineUsers.size}`);
  });
  
  // Join chat room
  socket.on('join_chat', (chatId) => {
    socket.join(`chat:${chatId}`);
    console.log(`?? Socket ${socket.id} joined chat: ${chatId}`);
  });
  
  // Leave chat room
  socket.on('leave_chat', (chatId) => {
    socket.leave(`chat:${chatId}`);
  });
  
  // Send message
  socket.on('send_message', async (data) => {
    try {
      const { chatId, content, type, replyTo } = data;
      
      // Check if user can send message
      const chat = await Chat.findById(chatId);
      if (!chat || !chat.participants.includes(socket.userId)) {
        return socket.emit('error', { message: 'Not authorized' });
      }
      
      // Create message
      const message = new Message({
        chatId,
        sender: socket.userId,
        type: type || 'text',
        content,
        replyTo
      });
      
      await message.save();
      
      // Update chat
      chat.lastMessage = message._id;
      chat.updatedAt = new Date();
      await chat.save();
      
      // Populate message for sending
      const populatedMessage = await Message.findById(message._id)
        .populate('sender', 'username profilePic')
        .populate('replyTo');
      
      // Emit to all participants
      chat.participants.forEach(participantId => {
        io.to(`user:${participantId}`).emit('new_message', {
          chatId,
          message: populatedMessage
        });
      });
      
    } catch (error) {
      console.error('Socket send_message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });
  
  // Typing indicator
  socket.on('typing', (data) => {
    const { chatId, isTyping } = data;
    socket.to(`chat:${chatId}`).emit('typing_indicator', {
      userId: socket.userId,
      chatId,
      isTyping
    });
  });
  
  // Message read receipt
  socket.on('message_read', async (data) => {
    try {
      const { messageId, chatId } = data;
      
      const message = await Message.findById(messageId);
      if (!message) return;
      
      if (!message.readBy.includes(socket.userId)) {
        message.readBy.push(socket.userId);
        await message.save();
        
        // Notify sender
        io.to(`user:${message.sender}`).emit('message_read', {
          messageId,
          readerId: socket.userId,
          chatId
        });
      }
    } catch (error) {
      console.error('Message read error:', error);
    }
  });
  
  // Call signaling
  socket.on('call_user', (data) => {
    const { to, offer, callType } = data;
    socket.to(`user:${to}`).emit('incoming_call', {
      from: socket.userId,
      offer,
      callType
    });
  });
  
  socket.on('call_answer', (data) => {
    const { to, answer } = data;
    socket.to(`user:${to}`).emit('call_accepted', {
      from: socket.userId,
      answer
    });
  });
  
  socket.on('call_ice_candidate', (data) => {
    const { to, candidate } = data;
    socket.to(`user:${to}`).emit('ice_candidate', {
      from: socket.userId,
      candidate
    });
  });
  
  socket.on('end_call', (data) => {
    const { to } = data;
    socket.to(`user:${to}`).emit('call_ended', {
      from: socket.userId
    });
  });
  
  // Disconnect
  socket.on('disconnect', async () => {
    if (socket.userId) {
      onlineUsers.delete(socket.userId);
      
      // Update user status
      await User.findByIdAndUpdate(socket.userId, { 
        lastSeen: new Date()
      });
      
      // Notify friends
      const user = await User.findById(socket.userId).populate('friends');
      if (user) {
        user.friends.forEach(friend => {
          io.to(`user:${friend._id}`).emit('user_status', {
            userId: socket.userId,
            status: 'offline'
          });
        });
      }
      
      console.log(`?? User ${socket.userId} disconnected. Online users: ${onlineUsers.size}`);
    }
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`?? Server running on port ${PORT}`);
  console.log(`?? Open http://localhost:${PORT} in your browser`);
});