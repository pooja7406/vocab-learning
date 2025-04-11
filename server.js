const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.error("Mongo error:", err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const wordSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    word: String,
    meaning: String
});

const User = mongoose.model('User', userSchema);
const Word = mongoose.model('Word', wordSchema);

const SECRET = process.env.JWT_SECRET || 'secret123';

// Middleware to verify token
function authenticate(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('Access denied.');

    try {
        const verified = jwt.verify(token, SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send('Invalid token.');
    }
}

// Register
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    try {
        const user = new User({ username, password: hashed });
        await user.save();
        res.status(201).send('User registered');
    } catch {
        res.status(400).send('Username already exists');
    }
});

// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).send('Invalid credentials');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Invalid credentials');

    const token = jwt.sign({ _id: user._id }, SECRET);
    res.json({ token });
});

// Get words for logged in user
app.get('/words', authenticate, async (req, res) => {
    const words = await Word.find({ userId: req.user._id });
    res.json(words);
});

// Add word
app.post('/words', authenticate, async (req, res) => {
    const { word, meaning } = req.body;
    const newWord = new Word({ word, meaning, userId: req.user._id });
    await newWord.save();
    res.status(201).json(newWord);
});

// Delete word
app.delete('/words/:id', authenticate, async (req, res) => {
    await Word.deleteOne({ _id: req.params.id, userId: req.user._id });
    res.status(204).send();
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
