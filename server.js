const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'thaionlinefund_super_secure_secret';

// Middleware
app.use(cors()); // อนุญาตให้ Frontend ยิง API เข้ามาได้
app.use(express.json());

// --- Mock Database ---
// ในระบบจริงให้เปลี่ยนจาก Array เป็นการเชื่อมต่อกับ PostgreSQL
let usersData = [
    { id: 'admin1', name: 'Webmaster', email: 'admin@thaionlinefund.com', passwordHash: bcrypt.hashSync('password', 10), role: 'admin', status: 'approved', phone: '0800000000', userType: 'admin', createdAt: Date.now() }
];

let projectsData = [];

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
    const token = jwt.sign({ id: user.id, role: user.role, status: user.status, name: user.name }, JWT_SECRET, { expiresIn: '15m' });
    res.json({ token, user, message: 'เข้าสู่ระบบสำเร็จ' });
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