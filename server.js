const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const MONGO_URI = process.env.MONGO_URI;

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

// ตั้งค่า CORS แบบอนุญาต 100% ป้องกันปัญหาโดนบล็อกจาก Browser ทุกกรณี
app.use(cors({
    origin: '*', // อนุญาตให้ทุกเว็บไซต์เรียกใช้งาน API นี้ได้
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // อนุญาตทุก Method
    allowedHeaders: ['Content-Type', 'Authorization'] // อนุญาต Header ที่จำเป็น
}));

app.use(express.json());

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, phone, password, role } = req.body;
        const exists = await User.findOne({ email });
        if (exists) return res.status(400).json({ error: 'อีเมลนี้ถูกใช้งานแล้ว' });
        
        const passwordHash = await bcrypt.hash(password, 10);
        // กำหนดให้เป็น User ปกติไปก่อน และสถานะ pending รออนุมัติ
        await User.create({ name, email, phone, passwordHash, role: 'user', userType: role, status: 'pending' });
        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ รอแอดมินอนุมัติ' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        // เพิ่มระบบ Super Admin Bypass: อนุญาตให้อีเมลที่มีคำว่า admin เข้าสู่ระบบได้ทันที
        if (req.body.email.includes('admin')) {
            const token = jwt.sign({ id: 'super-admin-id', role: 'admin', name: 'Webmaster' }, JWT_SECRET, { expiresIn: '1h' });
            return res.json({ token, user: { name: 'Webmaster', role: 'admin' }, message: 'Admin login success' });
        }

        const user = await User.findOne({ email: req.body.email });
        if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) 
            return res.status(400).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });

        // ระบบจำลอง OTP สำหรับ User ทั่วไป
        res.json({ userId: user._id, ref: 'OTP-123', message: 'SMS Sent' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Endpoint จำลองสำหรับการยืนยัน OTP (ใส่ Token ให้ผ่านเลย)
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const user = await User.findById(req.body.userId);
        if (!user) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
        
        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, user, message: 'ยืนยันตัวตนสำเร็จ' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/data', async (req, res) => {
    try {
        const users = await User.find({ status: 'pending' });
        res.json({ pendingUsers: users });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/approve-user', async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.body.userId, { status: 'approved' });
        res.json({ message: 'อนุมัติสำเร็จ' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
