const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const MONGO_URI = process.env.MONGO_URI; // เราจะใส่รหัสนี้ใน Render.com

mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('DB Connection Error:', err));

// Schema สำหรับ User
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    passwordHash: String,
    phone: String,
    role: String,
    userType: String,
    status: String,
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// Schema สำหรับ Project
const ProjectSchema = new mongoose.Schema({
    title: String,
    ownerId: String,
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});
const Project = mongoose.model('Project', ProjectSchema);

app.use(cors());
app.use(express.json());

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, phone, password, role } = req.body;
        const exists = await User.findOne({ email });
        if (exists) return res.status(400).json({ error: 'อีเมลนี้ถูกใช้งานแล้ว' });
        
        const passwordHash = await bcrypt.hash(password, 10);
        await User.create({ name, email, phone, passwordHash, role: 'user', userType: role, status: 'pending' });
        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ รอแอดมินอนุมัติ' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) 
        return res.status(400).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });

    // Admin Bypass
    if (user.role === 'admin') {
        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token, user, message: 'Admin login success' });
    }

    // OTP Logic (Simulated for brevity)
    res.json({ userId: user._id, ref: 'OTP-123', message: 'SMS Sent' });
});

app.get('/api/admin/data', async (req, res) => {
    const users = await User.find({ status: 'pending' });
    res.json({ pendingUsers: users });
});

app.post('/api/admin/approve-user', async (req, res) => {
    await User.findByIdAndUpdate(req.body.userId, { status: 'approved' });
    res.json({ message: 'อนุมัติสำเร็จ' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
