const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();

app.use(cors());
app.use(express.json());

// Set up storage for uploaded images
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads'); // specify your uploads folder
    fs.existsSync(uploadDir) || fs.mkdirSync(uploadDir); // create folder if it doesn't exist
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname); // keep original file name
  }
});

const upload = multer({ storage });

// Mock user data
const users = [
  { username: 'admin', password: bcrypt.hashSync('password123', 10), role: 'admin' },
  { username: 'user', password: bcrypt.hashSync('userpass', 10), role: 'user' }
];

// Login Route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign({ username: user.username, role: user.role }, 'secretkey', { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Middleware to check for admin access
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: 'No token provided' });

  jwt.verify(token, 'secretkey', (err, user) => {
    if (err || user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
    req.user = user;
    next();
  });
}

// Admin Route (protected)
app.get('/admin', authenticateToken, (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}! You have admin access.` });
});

// File Upload Route
app.post('/upload', authenticateToken, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }
  res.json({ message: 'File uploaded successfully!', file: req.file });
});

// Start server
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
