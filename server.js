const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios'); // สำหรับเชื่อมต่อ TBS API ส่ง SMS

const app = express();

// ตัวแปรสำหรับเก็บรหัส OTP ชั่วคราว
const otpStore = new Map();

// เปิด CORS ให้หน้าเว็บ EdgeOne เรียกใช้งานได้
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// ตั้งค่า Environment Variables
const JWT_SECRET = process.env.JWT_SECRET || 'thaionlinefund_super_secret_key';
const MONGO_URI = process.env.MONGO_URI;

// เชื่อมต่อ MongoDB
if (MONGO_URI) {
    mongoose.connect(MONGO_URI)
        .then(() => console.log('Connected to MongoDB'))
        .catch(err => console.error('DB Connection Error:', err.message));
} else {
    console.log('ยังไม่ได้ตั้งค่า MONGO_URI ใน Render');
}

// สร้างตารางข้อมูลผู้ใช้งาน (Schema)
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    phone: String,
    passwordHash: String,
    role: String,
    userType: String,
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// ==========================================
// 1. ระบบสมัครสมาชิก
// ==========================================
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

// ==========================================
// 2. ระบบเข้าสู่ระบบ และส่ง OTP ผ่าน ThaiBulkSMS (TBS)
// ==========================================
app.post('/api/auth/login', async (req, res) => {
    try {
        // ระบบ Super Admin Bypass: อนุญาตให้อีเมลที่มีคำว่า admin เข้าสู่ระบบได้ทันทีโดยไม่ต้องเช็ค DB/OTP
        if (req.body.email.includes('admin')) {
            const token = jwt.sign({ id: 'super-admin-id', role: 'admin', name: 'Webmaster' }, JWT_SECRET, { expiresIn: '1h' });
            return res.json({ token, user: { name: 'Webmaster', role: 'admin' }, message: 'Admin login success' });
        }

        // ตรวจสอบอีเมลและรหัสผ่าน
        const user = await User.findOne({ email: req.body.email });
        if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {
            return res.status(400).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
        }

        // ต้องมีเบอร์โทรศัพท์ที่กรอกตอนสมัครถึงจะส่ง SMS ได้
        if (!user.phone) {
            return res.status(400).json({ error: 'ไม่พบเบอร์โทรศัพท์ในระบบ โปรดติดต่อแอดมิน' });
        }

        // สร้างรหัส OTP 6 หลักของจริง (สุ่มตัวเลข)
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore.set(user._id.toString(), otpCode); // บันทึกไว้ตรวจสอบตอนผู้ใช้พิมพ์กลับมา

        // ดึงค่า API Key ของ TBS จาก Render
        const apiKey = process.env.TBS_API_KEY;
        const apiSecret = process.env.TBS_API_SECRET;
        
        if (apiKey && apiSecret) {
            try {
                // ส่ง SMS ผ่าน TBS API
                const data = new URLSearchParams();
                data.append('apiKey', apiKey);
                data.append('apiSecret', apiSecret);
                data.append('msisdn', user.phone); // ส่งไปที่เบอร์ของผู้ใช้งาน
                data.append('message', `รหัสยืนยัน (OTP) จาก ThaiOnlineFund คือ: ${otpCode}`);
                
                await axios.post('https://api-v2.thaibulksms.com/sms', data);
                console.log(`ส่ง SMS OTP ไปยังเบอร์ ${user.phone} สำเร็จ`);
            } catch (smsError) {
                console.error("ส่ง SMS ผ่าน TBS ไม่สำเร็จ:", smsError.message);
                return res.status(500).json({ error: 'ระบบส่ง SMS ขัดข้อง กรุณาลองใหม่ภายหลัง' });
            }
        } else {
            console.log(`[จำลอง SMS] รหัส OTP คือ: ${otpCode} (ยังไม่ได้ใส่คีย์ TBS ใน Render)`);
        }

        // แจ้งหน้าเว็บให้เปิดหน้าต่างกรอก OTP
        res.json({ userId: user._id, ref: 'OTP-' + otpCode.substring(0, 2) + 'XX', message: `ระบบได้ส่ง OTP ไปที่เบอร์ ${user.phone} แล้ว` });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==========================================
// 3. ระบบยืนยันรหัส OTP (ป้องกันการพิมพ์มั่ว)
// ==========================================
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { userId, otp } = req.body;
        
        // ดึงรหัสที่ระบบสร้างไว้มาเช็คเทียบกับที่ผู้ใช้กรอก
        const validOtp = otpStore.get(userId.toString());
        
        if (!validOtp || validOtp !== otp) {
            return res.status(400).json({ error: 'รหัส OTP ไม่ถูกต้อง หรือหมดอายุแล้ว' }); // พิมพ์มั่วจะโดนบล็อกตรงนี้
        }

        // ถ้ารหัสถูกต้อง ให้ลบ OTP ออกจากระบบทันทีเพื่อความปลอดภัย (ใช้ซ้ำไม่ได้)
        otpStore.delete(userId.toString());

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
        
        // สร้าง Token ยืนยันตัวตนให้ผู้ใช้
        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, user, message: 'ยืนยันตัวตนสำเร็จ' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==========================================
// 4. API สำหรับแอดมิน (ดึงข้อมูล และอนุมัติ)
// ==========================================
app.get('/api/admin/data', async (req, res) => {
    try {
        const users = await User.find({ status: 'pending' }).select('-passwordHash');
        res.json({ pendingUsers: users });
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/admin/approve-user', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.body.userId, { status: 'approved' }, { new: true });
        res.json({ message: 'อนุมัติผู้ใช้สำเร็จ', user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==========================================
// 5. API สำหรับรับข้อมูลเสนอโครงการธุรกิจ (Pitch)
// ==========================================
app.post('/api/projects/pitch', async (req, res) => {
    try {
        // ในระบบจริง จะนำข้อมูล req.body (ชื่อบริษัท, ยอดระดมทุน ฯลฯ) ไปบันทึกลง MongoDB ตาราง Projects
        // ตอนนี้ตอบกลับว่าได้รับข้อมูลแล้วไปก่อน
        res.status(201).json({ message: 'ได้รับข้อเสนอโครงการธุรกิจแล้ว ทีมงานจะติดต่อกลับเร็วๆ นี้' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
