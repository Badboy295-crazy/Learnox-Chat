const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs').promises;
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
app.use(express.static(path.join(__dirname, '.')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 3. File Upload Configuration
const storage = multer.diskStorage({
  destination: async function (req, file, cb) {
    const uploadDir = path.join(__dirname, 'uploads');
    try {
      await fs.access(uploadDir);
    } catch {
      await fs.mkdir(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// 4. Database Connection
const mongoURI = process.env.MONGO_URI; 
if (!mongoURI) {
    console.error("FATAL ERROR: MONGO_URI is not defined.");
}
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Atlas Connected'))
  .catch(err => console.log('DB Error:', err));

const JWT_SECRET = process.env.JWT_SECRET || 'secretKey123';

// 5. Database Models
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  avatar: { type: String, default: null },
  status: { type: String, default: 'offline' },
  lastSeen: { type: Date, default: Date.now },
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
  status: { type: String, default: 'sent' },
  edited: { type: Boolean, default: false },
  deleted: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now }
});

const friendRequestSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, default: 'pending' },
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

// 6. Auth Middleware
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

// Auth with profile picture
app.post('/api/register', upload.single('profilePic'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already exists' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const userData = { 
      name, 
      email, 
      password: hashedPassword,
      status: 'online'
    };
    
    // Add avatar if uploaded
    if (req.file) {
      userData.avatar = `/uploads/${req.file.filename}`;
    }
    
    const user = new User(userData);
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

// Update User Profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { name, currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Verify current password if changing password
    if (newPassword) {
      if (!currentPassword || !(await bcrypt.compare(currentPassword, user.password))) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }
      user.password = await bcrypt.hash(newPassword, 10);
    }
    
    // Update name if provided
    if (name) {
      user.name = name;
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

// Update Profile Picture
app.post('/api/user/profile-picture', authenticateToken, upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const user = await User.findById(req.user.id);
    
    // Delete old avatar if exists
    if (user.avatar && user.avatar.startsWith('/uploads/')) {
      const oldPath = path.join(__dirname, user.avatar);
      try {
        await fs.unlink(oldPath);
      } catch (err) {
        console.error('Error deleting old avatar:', err);
      }
    }
    
    user.avatar = `/uploads/${req.file.filename}`;
    await user.save();
    
    res.json({ 
      success: true, 
      avatarUrl: user.avatar 
    });
  } catch (error) {
    console.error('Update profile picture error:', error);
    res.status(500).json({ error: 'Failed to update profile picture' });
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
    const users = await User.find({ _id: { $ne: req.user.id } })
      .select('name email avatar status')
      .limit(50);
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
        status: friend.status,
        lastSeen: friend.lastSeen
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
    
    // Remove friendship
    await Friendship.findOneAndDelete({
      users: { $all: [req.user.id, friendId] }
    });
    
    // Remove friend requests between them
    await FriendRequest.deleteMany({
      $or: [
        { sender: req.user.id, receiver: friendId },
        { sender: friendId, receiver: req.user.id }
      ]
    });
    
    // Find and delete chat between them
    const chat = await Chat.findOne({
      participants: { $all: [req.user.id, friendId] }
    });
    
    if (chat) {
      // Delete all messages in the chat
      await Message.deleteMany({ chatId: chat._id });
      // Delete the chat
      await Chat.findByIdAndDelete(chat._id);
    }
    
    res.json({ success: true, message: 'Friend removed successfully' });
  } catch (error) {
    console.error('Remove friend error:', error);
    res.status(500).json({ error: 'Failed to remove friend' });
  }
});

// Get Chats
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({ participants: req.user.id })
      .populate('participants', 'name email avatar status')
      .sort({ lastMessageTime: -1 });
    
    const chatList = await Promise.all(chats.map(async (chat) => {
      const otherUser = chat.participants.find(p => p._id.toString() !== req.user.id.toString());
      
      const unreadCount = await Message.countDocuments({
        chatId: chat._id,
        receiver: req.user.id,
        status: { $in: ['sent', 'delivered'] },
        deleted: false
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

// Get last message with a user
app.get('/api/chats/last-message/:userId', authenticateToken, async (req, res) => {
  try {
    const chat = await Chat.findOne({
      participants: { $all: [req.user.id, req.params.userId] }
    });
    
    if (!chat) {
      return res.json({ lastMessage: 'No messages yet' });
    }
    
    const lastMessage = await Message.findOne({ chatId: chat._id })
      .sort({ timestamp: -1 })
      .limit(1);
    
    res.json({ 
      lastMessage: lastMessage ? lastMessage.text : 'No messages yet' 
    });
  } catch (error) {
    console.error('Get last message error:', error);
    res.status(500).json({ error: 'Failed to get last message' });
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
      status: { $in: ['sent', 'delivered'] },
      deleted: false
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
    
    let chat = await Chat.findOne({
      participants: { $all: [req.user.id, userId] }
    }).populate('participants', 'name email avatar');
    
    if (!chat) {
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

// Clear Chat
app.delete('/api/chats/:chatId/clear', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.includes(req.user.id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Mark all messages as deleted for current user
    await Message.updateMany(
      { chatId: chatId },
      { $addToSet: { deletedFor: req.user.id } }
    );
    
    // Update chat's last message
    chat.lastMessage = null;
    chat.lastMessageTime = null;
    await chat.save();
    
    res.json({ success: true });
  } catch (error) {
    console.error('Clear chat error:', error);
    res.status(500).json({ error: 'Failed to clear chat' });
  }
});

// Get Messages (with privacy)
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.includes(req.user.id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const messages = await Message.find({ 
      chatId,
      deletedFor: { $ne: req.user.id } // Don't show messages deleted by user
    })
      .populate('sender', 'name avatar')
      .populate('receiver', 'name avatar')
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
    
    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.includes(req.user.id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    await Message.updateMany(
      {
        chatId: chatId,
        receiver: req.user.id,
        status: { $in: ['sent', 'delivered'] }
      },
      { status: 'read' }
    );
    
    // Notify sender that messages were read
    const unreadMessages = await Message.find({
      chatId: chatId,
      receiver: req.user.id,
      status: 'read',
      sender: { $ne: req.user.id }
    });
    
    for (const msg of unreadMessages) {
      io.to(msg.sender.toString()).emit('message_status_update', {
        chatId: chatId,
        messageId: msg._id,
        status: 'read'
      });
    }
    
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
    
    const chat = await Chat.findById(chatId).populate('participants');
    if (!chat || !chat.participants.some(p => p._id.toString() === req.user.id.toString())) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const receiver = chat.participants.find(p => p._id.toString() !== req.user.id.toString());
    
    const message = new Message({
      chatId,
      sender: req.user.id,
      receiver: receiver._id,
      text,
      status: 'sent'
    });
    await message.save();
    
    chat.lastMessage = text;
    chat.lastMessageTime = new Date();
    await chat.save();
    
    await message.populate('sender', 'name avatar');
    await message.populate('receiver', 'name avatar');
    
    // Real-time send
    io.to(chatId).emit('new_message', message);
    
    // Emit delivered status after a short delay
    setTimeout(() => {
      message.status = 'delivered';
      message.save();
      io.to(chatId).emit('message_status_update', {
        chatId,
        messageId: message._id,
        status: 'delivered'
      });
    }, 1000);
    
    res.json(message);
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Edit Message
app.put('/api/messages/:messageId/edit', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { text } = req.body;
    
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Verify user is the sender
    if (message.sender.toString() !== req.user.id.toString()) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    message.text = text;
    message.edited = true;
    await message.save();
    
    // Update chat's last message if this was the last message
    const chat = await Chat.findById(message.chatId);
    if (chat.lastMessageTime && chat.lastMessageTime.getTime() === message.timestamp.getTime()) {
      chat.lastMessage = text;
      await chat.save();
    }
    
    // Notify receiver
    io.to(message.chatId.toString()).emit('message_edited', {
      chatId: message.chatId,
      messageId: message._id,
      newText: text
    });
    
    res.json({ success: true, message });
  } catch (error) {
    console.error('Edit message error:', error);
    res.status(500).json({ error: 'Failed to edit message' });
  }
});

// Delete Message (for everyone)
app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Verify user is the sender
    if (message.sender.toString() !== req.user.id.toString()) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    // Mark as deleted
    message.deleted = true;
    await message.save();
    
    // Update chat's last message if needed
    const chat = await Chat.findById(message.chatId);
    if (chat.lastMessage === message.text) {
      const lastMessage = await Message.findOne({
        chatId: message.chatId,
        _id: { $ne: message._id },
        deleted: false
      }).sort({ timestamp: -1 });
      
      chat.lastMessage = lastMessage ? lastMessage.text : null;
      chat.lastMessageTime = lastMessage ? lastMessage.timestamp : null;
      await chat.save();
    }
    
    // Notify all chat participants
    io.to(message.chatId.toString()).emit('message_deleted', {
      chatId: message.chatId,
      messageId: message._id
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
    
    const existingFriendship = await Friendship.findOne({
      users: { $all: [req.user.id, receiverId] }
    });
    
    if (existingFriendship) {
      return res.status(400).json({ error: 'Already friends' });
    }
    
    const existingRequest = await FriendRequest.findOne({
      sender: req.user.id,
      receiver: receiverId,
      status: 'pending'
    });
    
    if (existingRequest) {
      return res.status(400).json({ error: 'Friend request already sent' });
    }
    
    const request = new FriendRequest({
      sender: req.user.id,
      receiver: receiverId,
      status: 'pending'
    });
    await request.save();
    
    await request.populate('sender', 'name email avatar');
    
    io.to(receiverId).emit('friend_request_received', {
      _id: request._id,
      sender: request.sender,
      receiver: receiverId
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
    
    if (request.receiver._id.toString() !== req.user.id.toString()) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    request.status = action === 'accept' ? 'accepted' : 'rejected';
    await request.save();
    
    if (action === 'accept') {
      const friendship = new Friendship({
        users: [request.sender._id, request.receiver._id]
      });
      await friendship.save();
      
      const chat = new Chat({
        participants: [request.sender._id, request.receiver._id],
        lastMessage: null,
        lastMessageTime: null
      });
      await chat.save();
      
      const welcomeMessage = new Message({
        chatId: chat._id,
        sender: request.receiver._id,
        receiver: request.sender._id,
        text: 'Hello! ??',
        status: 'sent'
      });
      await welcomeMessage.save();
      
      chat.lastMessage = 'Hello! ??';
      chat.lastMessageTime = new Date();
      await chat.save();
      
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