const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios'); 

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'thaionlinefund_super_secure_secret';

const TBS_API_KEY = process.env.TBS_API_KEY || 'ใส่_API_KEY_ที่นี่';
const TBS_API_SECRET = process.env.TBS_API_SECRET || 'ใส่_API_SECRET_ที่นี่';

// Middleware
app.use(cors());
app.use(express.json());

// Mock Database
let usersData = [
    // ตรวจสอบตรงนี้: เปลี่ยน 0800000000 เป็นเบอร์มือถือจริงๆ ของคุณ (เช่น 0812345678)
    { id: 'admin1', name: 'Webmaster', email: 'admin@thaionlinefund.com', passwordHash: bcrypt.hashSync('password', 10), role: 'admin', status: 'approved', phone: '0812345678', userType: 'admin', createdAt: Date.now() }
];

let projectsData = [];
let otpStore = {}; 

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
    
    // --- ระบบพิเศษ: ถ้าเป็น Admin ให้เข้าสู่ระบบได้เลย ไม่ต้องใช้ OTP ---
    if (user.role === 'admin') {
        const token = jwt.sign({ id: user.id, role: user.role, status: user.status, name: user.name }, JWT_SECRET, { expiresIn: '15m' });
        return res.json({ token, user, message: 'ผู้ดูแลระบบเข้าสู่ระบบสำเร็จ' });
    }

    // --- ระบบสมาชิกปกติ: สุ่มรหัส OTP และบันทึกลงหน่วยความจำ ---
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const refCode = Math.random().toString(36).substring(2, 6).toUpperCase();
    otpStore[user.id] = { otp: otpCode, expires: Date.now() + 300000 }; // OTP หมดอายุใน 5 นาที

    // ส่ง SMS ผ่าน Thaibulksms ไปยังเบอร์ "ที่ผู้ใช้กรอกตอนสมัครสมาชิก (user.phone)"
    try {
        if (TBS_API_KEY && TBS_API_KEY !== 'ใส่_API_KEY_ที่นี่') {
            const params = new URLSearchParams();
            params.append('apiKey', TBS_API_KEY);
            params.append('apiSecret', TBS_API_SECRET);
            params.append('msisdn', user.phone); 
            params.append('message', `รหัส OTP ของคุณคือ ${otpCode} (Ref: ${refCode})`);
            params.append('sender', 'OTP_SMS'); // ชื่อผู้ส่งต้องตรงกับที่ Thaibulksms อนุมัติ

            await axios.post('https://api-v2.thaibulksms.com/sms', params);
            console.log(`ส่ง SMS ไปที่เบอร์ ${user.phone} สำเร็จ`);
        } else {
            console.log(`[โหมดทดสอบ] ส่งไปที่ ${user.phone}, OTP คือ: ${otpCode}`);
        }
    } catch (err) {
        // ดึง Error ของจริงจาก Thaibulksms มาแสดงให้รู้สาเหตุ
        const realError = err.response && err.response.data && err.response.data.error ? err.response.data.error.description : err.message;
        console.error("SMS Error Details:", realError);
        return res.status(500).json({ error: `ระบบ SMS ขัดข้อง: ${realError}` });
    }

    res.json({ userId: user.id, ref: refCode, message: 'ส่งรหัส OTP ไปยังเบอร์มือถือของคุณแล้ว' });
});

app.post('/api/auth/verify-otp', (req, res) => {
    const { userId, otp } = req.body;
    const record = otpStore[userId];

    if (!record) return res.status(400).json({ error: 'ไม่พบคำขอ OTP หรือรหัสหมดอายุแล้ว' });
    if (Date.now() > record.expires) return res.status(400).json({ error: 'รหัส OTP หมดอายุแล้ว' });
    if (record.otp !== otp) return res.status(400).json({ error: 'รหัส OTP ไม่ถูกต้อง' });

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
