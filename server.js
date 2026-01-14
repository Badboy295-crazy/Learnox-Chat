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
app.use(express.static(path.join(__dirname, '.')));

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

// 6. Authorization Middleware - Chat Access Check
const authorizeChatAccess = async (req, res, next) => {
  try {
    const chatId = req.params.chatId || req.body.chatId;
    if (!chatId) return next();
    
    const chat = await Chat.findById(chatId);
    if (!chat) return res.status(404).json({ error: 'Chat not found' });
    
    // Check if current user is a participant in this chat
    const isParticipant = chat.participants.some(
      participant => participant.toString() === req.user.id.toString()
    );
    
    if (!isParticipant) {
      return res.status(403).json({ 
        error: 'Access denied. You are not a participant in this chat.' 
      });
    }
    
    req.chat = chat;
    next();
  } catch (error) {
    console.error('Authorization error:', error);
    res.status(500).json({ error: 'Authorization failed' });
  }
};

// 7. Authorization Middleware - Friend Request Access Check
const authorizeFriendRequestAccess = async (req, res, next) => {
  try {
    const requestId = req.params.requestId;
    if (!requestId) return next();
    
    const request = await FriendRequest.findById(requestId);
    if (!request) return res.status(404).json({ error: 'Friend request not found' });
    
    // Check if current user is either sender or receiver of this request
    const isAuthorized = 
      request.sender.toString() === req.user.id.toString() ||
      request.receiver.toString() === req.user.id.toString();
    
    if (!isAuthorized) {
      return res.status(403).json({ 
        error: 'Access denied. You are not authorized to access this friend request.' 
      });
    }
    
    req.friendRequest = request;
    next();
  } catch (error) {
    console.error('Friend request authorization error:', error);
    res.status(500).json({ error: 'Authorization failed' });
  }
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
        status: user.status
      } 
    });
  } catch (e) { 
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error' }); 
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

// Search Users (Only non-friends)
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    // Get current friends
    const friendships = await Friendship.find({ users: req.user.id });
    const friendIds = friendships.flatMap(f => 
      f.users.map(id => id.toString()).filter(id => id !== req.user.id.toString())
    );
    
    // Find users who are not friends and not current user
    const users = await User.find({ 
      _id: { 
        $ne: req.user.id,
        $nin: friendIds
      } 
    }).select('name email status');
    
    res.json(users);
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// Get User Profile (Only if friends)
app.get('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Check if users are friends
    const friendship = await Friendship.findOne({
      users: { $all: [req.user.id, userId] }
    });
    
    if (!friendship) {
      return res.status(403).json({ 
        error: 'Access denied. You are not friends with this user.' 
      });
    }
    
    const user = await User.findById(userId).select('name email status lastSeen');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Get Friends
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    const friendships = await Friendship.find({ users: req.user.id })
      .populate('users', 'name email status lastSeen');
    
    const friends = friendships.map(friendship => {
      const friend = friendship.users.find(user => user._id.toString() !== req.user.id.toString());
      return {
        id: friend._id,
        name: friend.name,
        email: friend.email,
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

// Get Chats (Only user's own chats)
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({ participants: req.user.id })
      .populate('participants', 'name email status')
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

// Get unread messages count for a specific user (only if friends)
app.get('/api/chats/unread/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Check if users are friends
    const friendship = await Friendship.findOne({
      users: { $all: [req.user.id, userId] }
    });
    
    if (!friendship) {
      return res.status(403).json({ 
        error: 'Access denied. You are not friends with this user.' 
      });
    }
    
    const chat = await Chat.findOne({
      participants: { $all: [req.user.id, userId] }
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

// Create/Open Chat (Only with friends)
app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.body;
    
    // Check if users are friends
    const friendship = await Friendship.findOne({
      users: { $all: [req.user.id, userId] }
    });
    
    if (!friendship) {
      return res.status(403).json({ 
        error: 'You can only chat with friends. Send a friend request first.' 
      });
    }
    
    // Check if chat already exists
    let chat = await Chat.findOne({
      participants: { $all: [req.user.id, userId] }
    }).populate('participants', 'name email');
    
    if (!chat) {
      // Create new chat
      chat = new Chat({
        participants: [req.user.id, userId],
        lastMessage: null,
        lastMessageTime: null
      });
      await chat.save();
      await chat.populate('participants', 'name email');
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

// Get Messages (with authorization)
app.get('/api/chats/:chatId/messages', 
  authenticateToken, 
  authorizeChatAccess,
  async (req, res) => {
    try {
      const { chatId } = req.params;
      
      const messages = await Message.find({ chatId })
        .populate('sender', 'name')
        .populate('receiver', 'name')
        .sort('timestamp');
      
      res.json(messages);
    } catch (error) {
      console.error('Get messages error:', error);
      res.status(500).json({ error: 'Failed to get messages' });
    }
  }
);

// Mark messages as read (with authorization)
app.post('/api/chats/:chatId/read', 
  authenticateToken, 
  authorizeChatAccess,
  async (req, res) => {
    try {
      const { chatId } = req.params;
      
      // Mark all messages where receiver is current user as read
      await Message.updateMany(
        {
          chatId: chatId,
          receiver: req.user.id,
          status: { $in: ['sent', 'delivered'] }
        },
        { status: 'read' }
      );
      
      res.json({ success: true });
    } catch (error) {
      console.error('Mark as read error:', error);
      res.status(500).json({ error: 'Failed to mark as read' });
    }
  }
);

// Send Message (with authorization)
app.post('/api/messages', 
  authenticateToken, 
  authorizeChatAccess,
  async (req, res) => {
    try {
      const { chatId, text } = req.body;
      
      // Find receiver (other participant)
      const receiver = req.chat.participants.find(
        p => p._id.toString() !== req.user.id.toString()
      );
      
      const message = new Message({
        chatId,
        sender: req.user.id,
        receiver: receiver._id,
        text,
        status: 'sent'
      });
      await message.save();
      
      // Update chat's last message
      req.chat.lastMessage = text;
      req.chat.lastMessageTime = new Date();
      await req.chat.save();
      
      // Populate sender and receiver details
      await message.populate('sender', 'name');
      await message.populate('receiver', 'name');
      
      // Real-time send only to chat participants
      io.to(chatId).emit('new_message', message);
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
  }
);

// Friend Requests - Received (only user's own)
app.get('/api/friend-requests/received', authenticateToken, async (req, res) => {
  try {
    const requests = await FriendRequest.find({
      receiver: req.user.id,
      status: 'pending'
    }).populate('sender', 'name email');
    
    res.json(requests);
  } catch (error) {
    console.error('Get received requests error:', error);
    res.status(500).json({ error: 'Failed to get friend requests' });
  }
});

// Friend Requests - Sent (only user's own)
app.get('/api/friend-requests/sent', authenticateToken, async (req, res) => {
  try {
    const requests = await FriendRequest.find({
      sender: req.user.id,
      status: 'pending'
    }).populate('receiver', 'name email');
    
    res.json(requests);
  } catch (error) {
    console.error('Get sent requests error:', error);
    res.status(500).json({ error: 'Failed to get sent requests' });
  }
});

// Send Friend Request
app.post('/api/friend-requests/send', authenticateToken, async (req, res) => {
  try {
    const { receiverId } = req.body;
    
    // Cannot send request to self
    if (receiverId === req.user.id) {
      return res.status(400).json({ error: 'Cannot send friend request to yourself' });
    }
    
    // Check if already friends
    const existingFriendship = await Friendship.findOne({
      users: { $all: [req.user.id, receiverId] }
    });
    
    if (existingFriendship) {
      return res.status(400).json({ error: 'Already friends' });
    }
    
    // Check if request already exists
    const existingRequest = await FriendRequest.findOne({
      $or: [
        { sender: req.user.id, receiver: receiverId, status: 'pending' },
        { sender: receiverId, receiver: req.user.id, status: 'pending' }
      ]
    });
    
    if (existingRequest) {
      return res.status(400).json({ 
        error: existingRequest.sender.toString() === req.user.id.toString() 
          ? 'Friend request already sent' 
          : 'This user has already sent you a friend request' 
      });
    }
    
    // Create new friend request
    const request = new FriendRequest({
      sender: req.user.id,
      receiver: receiverId,
      status: 'pending'
    });
    await request.save();
    
    // Populate sender info
    await request.populate('sender', 'name email');
    
    // Notify receiver in real-time
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

// Accept/Reject Friend Request (with authorization)
app.post('/api/friend-requests/:requestId/:action', 
  authenticateToken, 
  authorizeFriendRequestAccess,
  async (req, res) => {
    try {
      const { requestId, action } = req.params;
      
      if (!['accept', 'reject'].includes(action)) {
        return res.status(400).json({ error: 'Invalid action' });
      }
      
      // Verify current user is the receiver (only receiver can accept/reject)
      if (req.friendRequest.receiver.toString() !== req.user.id.toString()) {
        return res.status(403).json({ 
          error: 'Only the receiver can accept or reject friend requests' 
        });
      }
      
      // Update request status
      req.friendRequest.status = action === 'accept' ? 'accepted' : 'rejected';
      await req.friendRequest.save();
      
      if (action === 'accept') {
        // Create friendship
        const friendship = new Friendship({
          users: [req.friendRequest.sender, req.friendRequest.receiver]
        });
        await friendship.save();
        
        // Create chat for the new friends
        const chat = new Chat({
          participants: [req.friendRequest.sender, req.friendRequest.receiver],
          lastMessage: null,
          lastMessageTime: null
        });
        await chat.save();
        
        // Send welcome message
        const welcomeMessage = new Message({
          chatId: chat._id,
          sender: req.friendRequest.receiver,
          receiver: req.friendRequest.sender,
          text: 'Hello! ??',
          status: 'sent'
        });
        await welcomeMessage.save();
        
        // Update chat's last message
        chat.lastMessage = 'Hello! ??';
        chat.lastMessageTime = new Date();
        await chat.save();
        
        // Notify sender in real-time
        io.to(req.friendRequest.sender.toString()).emit('friend_request_accepted', {
          acceptorId: req.friendRequest.receiver,
          acceptorName: req.user.name
        });
      }
      
      res.json({ 
        success: true, 
        message: `Friend request ${action}ed`,
        request: req.friendRequest
      });
    } catch (error) {
      console.error('Handle friend request error:', error);
      res.status(500).json({ error: `Failed to ${action} friend request` });
    }
  }
);

// Helper: Generate consistent Chat ID between two users
function getChatId(user1, user2) {
  return [user1, user2].sort().join('_');
}

// Socket Logic with Privacy
io.on('connection', (socket) => {
  console.log('New client connected');
  
  socket.on('join_user', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined their room`);
  });
  
  socket.on('join_chat', async (chatId) => {
    try {
      // Verify user has access to this chat
      const chat = await Chat.findById(chatId);
      if (!chat) {
        socket.emit('error', { message: 'Chat not found' });
        return;
      }
      
      const isParticipant = chat.participants.some(
        participant => participant.toString() === socket.userId
      );
      
      if (!isParticipant) {
        socket.emit('error', { message: 'Access denied to this chat' });
        return;
      }
      
      socket.join(chatId);
      console.log(`User joined chat ${chatId}`);
    } catch (error) {
      console.error('Join chat error:', error);
      socket.emit('error', { message: 'Failed to join chat' });
    }
  });
  
  socket.on('update_status', async (data) => {
    const { userId, status } = data;
    
    // Verify socket is authorized for this user
    if (socket.userId !== userId) {
      socket.emit('error', { message: 'Unauthorized status update' });
      return;
    }
    
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
  
  socket.on('typing', async (data) => {
    const { chatId, userId } = data;
    
    // Verify user has access to this chat
    const chat = await Chat.findById(chatId);
    if (!chat) return;
    
    const isParticipant = chat.participants.some(
      participant => participant.toString() === userId
    );
    
    if (!isParticipant) return;
    
    // Send typing indicator only to other participants
    chat.participants.forEach(participant => {
      if (participant.toString() !== userId) {
        socket.to(participant.toString()).emit('typing', {
          chatId,
          userId
        });
      }
    });
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Middleware to attach user ID to socket
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error('Authentication error'));
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.userId = decoded.id;
    next();
  } catch (error) {
    next(new Error('Authentication error'));
  }
});

// Serve Index
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));