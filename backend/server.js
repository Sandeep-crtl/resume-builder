// server.js - Google Auth Removed
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/resume-builder';

// Middleware
app.use(cors({
    origin: 'https://resume-builder-cha5.onrender.com'
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Routes (replace with your actual route files)
import authRoutes from './routes/auth.js';
import resumeRoutes from './routes/resumes.js';

app.use('/auth', authRoutes);
app.use('/resumes', resumeRoutes);

// MongoDB Connection
mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, minlength: 6 },
    createdAt: { type: Date, default: Date.now }
});

const resumeSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    data: {
        personalInfo: {
            name: String, title: String, email: String, phone: String, summary: String
        },
        experience: [{ company: String, position: String, duration: String, description: String }],
        education: [{ institution: String, degree: String, year: String }],
        skills: [String],
        projects: [{ name: String, description: String }],
        certificates: [String]
    },
    formatting: {
        font: { type: String, default: 'Inter' },
        fontSize: { type: String, default: '14' },
        primaryColor: { type: String, default: '#3B82F6' },
        width: { type: Number, default: 80 },
        height: { type: Number, default: 100 }
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

resumeSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

const User = mongoose.model('User', userSchema);
const Resume = mongoose.model('Resume', resumeSchema);

// JWT Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({ message: 'User registered', token, user: { id: user._id, name: user.name, email: user.email } });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

        res.json({ message: 'Login successful', token, user: { id: user._id, name: user.name, email: user.email } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ user });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/resumes', authenticateToken, async (req, res) => {
    try {
        const resumes = await Resume.find({ userId: req.user.userId }).select('title createdAt updatedAt').sort({ updatedAt: -1 });
        const formatted = resumes.map(r => ({ id: r._id, title: r.title, lastModified: formatLastModified(r.updatedAt) }));
        res.json({ resumes: formatted });
    } catch (error) {
        console.error('Get resumes error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/resumes/:id', authenticateToken, async (req, res) => {
    try {
        const resume = await Resume.findOne({ _id: req.params.id, userId: req.user.userId });
        if (!resume) return res.status(404).json({ error: 'Resume not found' });
        res.json({ resume });
    } catch (error) {
        console.error('Get resume error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/resumes', authenticateToken, async (req, res) => {
    try {
        const { title } = req.body;
        if (!title) return res.status(400).json({ error: 'Title is required' });

        const resume = new Resume({
            title,
            userId: req.user.userId,
            data: {
                personalInfo: { name: 'John Doe', title: 'Software Engineer', email: 'john@example.com', phone: '123-456', summary: 'Experienced dev.' },
                experience: [], education: [], skills: [], projects: [], certificates: []
            }
        });

        await resume.save();

        res.status(201).json({ message: 'Resume created', resume: { id: resume._id, title: resume.title, lastModified: formatLastModified(resume.updatedAt) } });
    } catch (error) {
        console.error('Create resume error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/resumes/:id', authenticateToken, async (req, res) => {
    try {
        const { title, data, formatting } = req.body;
        const updateData = {};
        if (title) updateData.title = title;
        if (data) updateData.data = data;
        if (formatting) updateData.formatting = formatting;

        const resume = await Resume.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.userId },
            updateData,
            { new: true }
        );

        if (!resume) return res.status(404).json({ error: 'Resume not found' });
        res.json({ message: 'Resume updated', resume });
    } catch (error) {
        console.error('Update resume error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/resumes/:id', authenticateToken, async (req, res) => {
    try {
        const resume = await Resume.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
        if (!resume) return res.status(404).json({ error: 'Resume not found' });
        res.json({ message: 'Resume deleted' });
    } catch (error) {
        console.error('Delete resume error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

function formatLastModified(date) {
    const diff = Math.floor((new Date() - date) / (1000 * 60 * 60 * 24));
    if (diff === 0) return 'Today';
    if (diff === 1) return '1 day ago';
    if (diff < 7) return `${diff} days ago`;
    if (diff < 30) return `${Math.floor(diff / 7)} week(s) ago`;
    return `${Math.floor(diff / 30)} month(s) ago`;
}

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

app.use('/api', (req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

export default app;