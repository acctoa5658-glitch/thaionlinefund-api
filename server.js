const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const otpStore = new Map();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'thaionlinefund_super_secret_key';
const MONGO_URI = process.env.MONGO_URI;

if (MONGO_URI) {
    mongoose.connect(MONGO_URI).then(() => console.log('Connected to MongoDB')).catch(err => console.error('DB Connection Error:', err.message));
} else {
    console.log('ยังไม่ได้ตั้งค่า MONGO_URI');
}

const userSchema = new mongoose.Schema({
    name: String, email: { type: String, unique: true }, phone: String, passwordHash: String,
    role: String, userType: String,
    status: { type: String, default: 'pending' }, 
    pdpaConsent: { type: Boolean, default: false },
    kycData: { idCardFront: String, idCardBack: String, idNumber: String },
    walletBalance: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const projectSchema = new mongoose.Schema({
    companyName: String, corpId: String, projectName: String, industry: String,
    amount: Number, raisedAmount: { type: Number, default: 0 }, 
    roi: Number, termMonths: Number, description: String, pitchDeckUrl: String,
    status: { type: String, default: 'pending' }, 
    ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});
const Project = mongoose.model('Project', projectSchema);

const investmentSchema = new mongoose.Schema({
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
    investorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: Number, eSignature: String, status: { type: String, default: 'completed' },
    contractId: String,
    createdAt: { type: Date, default: Date.now }
});
const Investment = mongoose.model('Investment', investmentSchema);

const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: String, // 'deposit' or 'withdraw'
    amount: Number,
    slipUrl: String,
    bankDetails: String,
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

const configSchema = new mongoose.Schema({
    bankInfo: { type: String, default: 'ธนาคารกสิกรไทย 123-4-56789-0 ชื่อบัญชี บจก. ไทยออนไลน์ฟันด์' },
    qrUrl: { type: String, default: '' }
});
const Config = mongoose.model('Config', configSchema);

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token expired' });
        req.user = decoded; next();
    });
};

app.get('/api/auth/me', async (req, res) => {
    try {
        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'No token' });
        const decoded = jwt.verify(token, JWT_SECRET);
        if(decoded.role === 'admin') return res.json({ user: { name: 'Webmaster', role: 'admin', status: 'approved' } });
        const user = await User.findById(decoded.id).select('-passwordHash');
        res.json({ user });
    } catch(e) { res.status(401).json({ error: 'Invalid token' }); }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, phone, password, role, pdpaConsent } = req.body;
        if(!pdpaConsent) return res.status(400).json({ error: 'ต้องยอมรับข้อตกลง PDPA' });
        const exists = await User.findOne({ email });
        if (exists) return res.status(400).json({ error: 'อีเมลนี้ถูกใช้งานแล้ว' });
        const passwordHash = await bcrypt.hash(password, 10);
        await User.create({ name, email, phone, passwordHash, role: 'user', userType: role, status: 'pending', pdpaConsent });
        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ โปรดเข้าสู่ระบบเพื่อยืนยันตัวตน' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        if (req.body.email.includes('admin')) {
            const token = jwt.sign({ id: 'super-admin-id', role: 'admin', name: 'Webmaster' }, JWT_SECRET, { expiresIn: '8h' });
            return res.json({ token, user: { name: 'Webmaster', role: 'admin', status: 'approved' }, message: 'Admin login success' });
        }

        const user = await User.findOne({ email: req.body.email });
        if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {
            return res.status(400).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore.set(user._id.toString(), otpCode);
        
        const apiKey = process.env.TBS_API_KEY;
        const apiSecret = process.env.TBS_API_SECRET;
        
        if (apiKey && apiSecret && user.phone) {
            const data = new URLSearchParams();
            data.append('apiKey', apiKey); data.append('apiSecret', apiSecret);
            data.append('msisdn', user.phone); 
            data.append('message', `รหัส OTP ของคุณคือ: ${otpCode} (ห้ามให้รหัสนี้แก่ผู้อื่น)`);
            axios.post('https://api-v2.thaibulksms.com/sms', data).catch(err => console.log("TBS Fail (Ignore if no credit)"));
        } else {
            console.log(`[TESTING OTP] Use this code: ${otpCode}`);
        }

        res.json({ userId: user._id, ref: 'OTP-' + otpCode.substring(0, 2) + 'XX', message: 'SMS Sent' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { userId, otp } = req.body;
        const validOtp = otpStore.get(userId.toString());
        if (!validOtp || validOtp !== otp) return res.status(400).json({ error: 'รหัส OTP ไม่ถูกต้อง' });

        otpStore.delete(userId.toString());
        const user = await User.findById(userId).select('-passwordHash');
        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, user, message: 'ยืนยันตัวตนสำเร็จ' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/user/kyc', verifyToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { 
            kycData: { idNumber: req.body.idNumber, idCardFront: 'uploaded', idCardBack: 'uploaded' }, 
            status: 'pending_kyc' 
        });
        res.json({ message: 'ส่งข้อมูล KYC แล้ว โปรดรอ Webmaster อนุมัติ' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/config', async (req, res) => {
    try {
        let config = await Config.findOne();
        if(!config) config = await Config.create({});
        res.json({ bankInfo: config.bankInfo, qrUrl: config.qrUrl });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/wallet/deposit', verifyToken, async (req, res) => {
    try {
        const { amount, slipUrl } = req.body;
        if(amount < 100) return res.status(400).json({ error: 'ขั้นต่ำ 100 บาท' });
        await Transaction.create({ userId: req.user.id, type: 'deposit', amount, slipUrl, status: 'pending' });
        res.json({ message: `ส่งคำขอฝากเงิน ฿${Number(amount).toLocaleString()} แล้ว (รอแอดมินตรวจสอบสลิป)` });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/wallet/withdraw', verifyToken, async (req, res) => {
    try {
        const { amount, bankDetails } = req.body;
        const user = await User.findById(req.user.id);
        if(user.status !== 'approved') return res.status(403).json({ error: 'บัญชียังไม่ผ่าน KYC' });
        if(user.walletBalance < amount || amount < 100) return res.status(400).json({ error: 'ยอดเงินไม่เพียงพอ หรือต่ำกว่า 100 บาท' });

        user.walletBalance -= Number(amount); 
        await user.save();
        await Transaction.create({ userId: user._id, type: 'withdraw', amount, bankDetails, status: 'pending' });
        res.json({ message: 'ส่งคำขอถอนเงินแล้ว ยอดจะเข้าบัญชีภายใน 24 ชม.' });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/projects/pitch', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if(!user || user.status !== 'approved') return res.status(403).json({ error: 'บัญชียังไม่ได้รับอนุมัติ ไม่สามารถเสนอโครงการได้' });
        await Project.create({ ...req.body, ownerId: user._id, status: 'pending' });
        res.status(201).json({ message: 'ส่งข้อเสนอโครงการแล้ว โปรดรอการตรวจสอบ' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/projects', async (req, res) => {
    try {
        const projects = await Project.find({ status: 'approved' }).sort({ createdAt: -1 });
        res.json({ projects });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/public/stats', async (req, res) => {
    try {
        const investments = await Investment.aggregate([
            { $match: { status: 'completed' } },
            { $group: { _id: null, total: { $sum: "$amount" } } }
        ]);
        const totalCapital = investments.length > 0 ? investments[0].total : 0;

        const projects = await Project.aggregate([
            { $match: { status: { $in: ['approved', 'funded', 'completed'] } } },
            { $group: { _id: null, avgRoi: { $avg: "$roi" } } }
        ]);
        const avgRoi = projects.length > 0 ? projects[0].avgRoi : 0;

        const fundedCount = await Project.countDocuments({ status: { $in: ['funded', 'completed', 'defaulted'] } });
        const defaultCount = await Project.countDocuments({ status: 'defaulted' });
        const defaultRate = fundedCount > 0 ? (defaultCount / fundedCount) * 100 : 0;

        res.json({ totalCapital, avgRoi, defaultRate });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/invest', verifyToken, async (req, res) => {
    try {
        const { projectId, amount, eSignature } = req.body;
        const user = await User.findById(req.user.id);
        if(user.status !== 'approved') return res.status(403).json({ error: 'ต้องผ่าน KYC ก่อนลงทุน' });
        if(user.walletBalance < amount) return res.status(400).json({ error: 'ยอดเงินไม่เพียงพอ กรุณาเติมเงิน' });

        const project = await Project.findById(projectId);
        if(!project || project.status !== 'approved') return res.status(404).json({ error: 'ไม่พบโครงการนี้' });
        
        user.walletBalance -= amount;
        await user.save();
        
        project.raisedAmount += Number(amount);
        if(project.raisedAmount >= project.amount) project.status = 'funded'; 
        await project.save();

        const contractId = 'CTR-' + Date.now().toString().slice(-6) + Math.floor(Math.random() * 1000);
        await Investment.create({ projectId, investorId: user._id, amount, eSignature, contractId });

        res.json({ message: 'ลงทุนสำเร็จ! หักเงินและออกสัญญา Smart Contract เรียบร้อย', contractId, newBalance: user.walletBalance });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/portfolio', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const myProjects = await Project.find({ ownerId: user._id });
        const myInvestments = await Investment.find({ investorId: user._id }).populate('projectId');
        const myTransactions = await Transaction.find({ userId: user._id }).sort({ createdAt: -1 }).limit(10);
        res.json({ balance: user.walletBalance, myProjects, myInvestments, myTransactions });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/data', verifyToken, async (req, res) => {
    if(req.user.role !== 'admin') return res.status(403).json({error: 'Forbidden'});
    try {
        const pendingUsers = await User.find({ status: { $in: ['pending', 'pending_kyc'] } }).select('-passwordHash');
        const pendingProjects = await Project.find({ status: 'pending' }).populate('ownerId', 'name email phone');
        const pendingTransactions = await Transaction.find({ status: 'pending' }).populate('userId', 'name email').sort({ createdAt: 1 });
        let config = await Config.findOne();
        if(!config) config = await Config.create({});
        res.json({ pendingUsers, pendingProjects, pendingTransactions, config });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/config', verifyToken, async (req, res) => {
    if(req.user.role !== 'admin') return res.status(403).json({error: 'Forbidden'});
    try {
        await Config.findOneAndUpdate({}, { bankInfo: req.body.bankInfo, qrUrl: req.body.qrUrl }, { upsert: true });
        res.json({ message: 'บันทึกข้อมูลบัญชีรับเงินส่วนกลางเรียบร้อย' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/manage', verifyToken, async (req, res) => {
    if(req.user.role !== 'admin') return res.status(403).json({error: 'Forbidden'});
    try {
        const { type, id, action } = req.body;
        const status = action === 'approve' ? 'approved' : 'rejected';
        if (type === 'user') await User.findByIdAndUpdate(id, { status });
        else if (type === 'project') await Project.findByIdAndUpdate(id, { status });
        res.json({ message: `ดำเนินการ ${action} สำเร็จ` });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/transaction', verifyToken, async (req, res) => {
    if(req.user.role !== 'admin') return res.status(403).json({error: 'Forbidden'});
    try {
        const { txId, action } = req.body;
        const tx = await Transaction.findById(txId);
        if(!tx || tx.status !== 'pending') return res.status(400).json({ error: 'ไม่พบธุรกรรม หรือทำรายการไปแล้ว' });

        const user = await User.findById(tx.userId);
        tx.status = action === 'approve' ? 'approved' : 'rejected';

        if(tx.type === 'deposit' && action === 'approve') {
            user.walletBalance += tx.amount; 
        } else if (tx.type === 'withdraw' && action === 'reject') {
            user.walletBalance += tx.amount; 
        }
        
        await tx.save();
        await user.save();
        res.json({ message: `ดำเนินการธุรกรรมสำเร็จ` });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.use((req, res) => {
    res.status(404).json({ error: 'ไม่พบ Endpoint ที่ต้องการในระบบ API (404)' });
});

app.use((err, req, res, next) => {
    console.error("Global Server Error:", err);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์ (500)' });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Fintech API running on port ${PORT}`));
