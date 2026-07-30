const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios'); // เพิ่ม axios สำหรับยิง API Thaibulksms

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'thaionlinefund_super_secure_secret';

// ตั้งค่า Thaibulksms API (เดี๋ยวเราจะไปใส่ในเว็บ Render ทีหลัง)
const TBS_API_KEY = process.env.TBS_API_KEY || 'ใส่_API_KEY_ที่นี่';
const TBS_API_SECRET = process.env.TBS_API_SECRET || 'ใส่_API_SECRET_ที่นี่';

// Middleware
app.use(cors());
    { id: 'admin1', name: 'Webmaster', email: 'admin@thaionlinefund.com', passwordHash: bcrypt.hashSync('password', 10), role: 'admin', status: 'approved', phone: '0800000000', userType: 'admin', createdAt: Date.now() }
];

let projectsData = [];
let otpStore = {}; // หน่วยความจำชั่วคราวสำหรับเก็บรหัส OTP 

// --- Middleware ตรวจ Token ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'ปฏิเสธการเข้าถึง' });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Session หมดอายุ' });
        req.user = decoded;
        next();
    });
};

// --- Endpoints ---
app.get('/api/public/data', (req, res) => {
    res.json({ projects: projectsData.filter(p => p.status === 'approved') });
});

app.post('/api/auth/register', async (req, res) => {
    const { name, email, phone, password, role } = req.body;
    if (usersData.some(u => u.email === email)) return res.status(400).json({ error: 'อีเมลซ้ำ' });
    const passwordHash = await bcrypt.hash(password, 10);
    usersData.push({ id: `u_${Date.now()}`, name, email, phone, passwordHash, role: 'user', userType: role, status: 'pending', createdAt: Date.now() });
    res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ รอแอดมินอนุมัติ' });
});

app.post('/api/auth/login', async (req, res) => {
    const user = usersData.find(u => u.email === req.body.email);
    if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) return res.status(400).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
    
    // 1. สุ่มรหัส OTP 6 หลัก และรหัสอ้างอิง (Ref)
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const refCode = Math.random().toString(36).substring(2, 6).toUpperCase();
    
    // 2. บันทึก OTP ไว้ในระบบ ให้เวลา 5 นาที (300000 ms) ก่อนหมดอายุ
    otpStore[user.id] = { otp: otpCode, expires: Date.now() + 300000 };

    // 3. ส่ง SMS จริงผ่าน Thaibulksms
    try {
        if (TBS_API_KEY !== 'ใส่_API_KEY_ที่นี่') {
            const params = new URLSearchParams();
            params.append('apiKey', TBS_API_KEY);
            params.append('apiSecret', TBS_API_SECRET);
            params.append('msisdn', user.phone);
            params.append('message', `รหัส OTP สำหรับเข้าสู่ระบบ ThaiOnlineFund คือ ${otpCode} (Ref: ${refCode}) ห้ามบอกรหัสนี้กับผู้อื่น`);
            params.append('sender', 'SMS'); // ชื่อผู้ส่ง (ถ้าไม่ได้ซื้อชื่อไว้ จะขึ้นว่า SMS)

            await axios.post('https://api-v2.thaibulksms.com/sms', params);
            console.log(`ส่ง SMS ไปที่เบอร์ ${user.phone} สำเร็จ`);
        } else {
            console.log(`[โหมดทดสอบ] ไม่ได้ใส่ API Key -- OTP สำหรับเบอร์ ${user.phone} คือ: ${otpCode}`);
        }
    } catch (err) {
        console.error("SMS Error:", err.response ? err.response.data : err.message);
        return res.status(500).json({ error: 'ไม่สามารถส่ง SMS ได้ โปรดตรวจสอบว่าเบอร์ถูกต้องและเครดิต SMS คงเหลือ' });
    }

    res.json({ userId: user.id, ref: refCode, message: 'ส่งรหัส OTP ไปยังเบอร์มือถือแล้ว' });
});

// เพิ่ม API สำหรับตรวจรหัส OTP ที่ผู้ใช้กรอกเข้ามา
app.post('/api/auth/verify-otp', (req, res) => {
    const { userId, otp } = req.body;
    const record = otpStore[userId];

    if (!record) return res.status(400).json({ error: 'ไม่พบคำขอ OTP หรือรหัสหมดอายุแล้ว' });
    if (Date.now() > record.expires) return res.status(400).json({ error: 'รหัส OTP หมดอายุแล้ว (เกิน 5 นาที)' });
    if (record.otp !== otp) return res.status(400).json({ error: 'รหัส OTP ไม่ถูกต้อง' });

    // ถ้ารหัสถูก ให้ลบรหัสทิ้ง และอนุญาตให้เข้าสู่ระบบ (ออก Token)
    delete otpStore[userId];
    const user = usersData.find(u => u.id === userId);
    const token = jwt.sign({ id: user.id, role: user.role, status: user.status, name: user.name }, JWT_SECRET, { expiresIn: '15m' });
    
    res.json({ token, user, message: 'ยืนยันตัวตนสำเร็จ' });
});

app.post('/api/projects/apply', verifyToken, (req, res) => {
    if (req.user.status !== 'approved') return res.status(403).json({ error: 'บัญชียังไม่ผ่านการอนุมัติ' });
    projectsData.unshift({ ...req.body, id: `p_${Date.now()}`, ownerId: req.user.id, raisedAmount: 0, status: 'pending', createdAt: Date.now() });
    res.json({ message: 'ส่งคำขอสำเร็จ' });
});

app.get('/api/admin/data', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'ไม่มีสิทธิ์' });
    res.json({ pendingUsers: usersData.filter(u => u.status === 'pending'), pendingProjects: projectsData.filter(p => p.status === 'pending') });
});

app.post('/api/admin/approve-user', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'ไม่มีสิทธิ์' });
    const user = usersData.find(u => u.id === req.body.userId);
    if (user) user.status = 'approved';
    res.json({ message: 'อนุมัติผู้ใช้สำเร็จ' });
});

app.post('/api/admin/approve-project', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'ไม่มีสิทธิ์' });
    const proj = projectsData.find(p => p.id === req.body.projectId);
    if (proj) proj.status = 'approved';
    res.json({ message: 'อนุมัติโครงการสำเร็จ' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
