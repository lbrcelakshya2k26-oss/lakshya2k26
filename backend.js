require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
require('dotenv').config();
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const { SESv2Client, SendEmailCommand } = require("@aws-sdk/client-sesv2");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, UpdateCommand, DeleteCommand, QueryCommand } = require("@aws-sdk/lib-dynamodb");
const chatRoute = require('./chatRoute'); 


// const Razorpay = require('razorpay'); // Payment Disabled for now
const Razorpay = require('razorpay');
const crypto = require('crypto'); // Built-in Node module for security
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const app = express();

// --- 1. CONFIGURATION ---
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- SERVE ASSETS & SCRIPTS (SECURE) ---
app.use('/assets', express.static(path.join(__dirname, 'assets')));
// Point to public/js instead of just js
app.use('/js', express.static(path.join(__dirname, 'public/js')));
// Point to public/static instead of just static
app.use('/static', express.static(path.join(__dirname, 'public/static')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'lakshya_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// --- RAZORPAY SETUP ---
// --- RAZORPAY SETUP ---
// Define keys in variables first so we can reuse them
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || 'rzp_test_Rj1XO8nMv3xR7J';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || 'XqfcDBCtT3RD570yw8fGT43u';

const razorpay = new Razorpay({
    key_id: RAZORPAY_KEY_ID,
    key_secret: RAZORPAY_KEY_SECRET
});

// --- 2. AWS SETUP (UPDATED WITH YOUR CREDENTIALS) ---

// DynamoDB Setup
const client = new DynamoDBClient({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIAT4YSUMZD755UHGW7',
        secretAccessKey: '+7xyGRP/P+5qZD955qgrC8GwvuOsA33wwzwe6abl'
    }
});
const docClient = DynamoDBDocumentClient.from(client);

const s3Client = new S3Client({
    region: process.env.AWS_REGION || 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIAT4YSUMZD755UHGW7',
        secretAccessKey: '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'
    }
});

// SES Setup
const sesClient = new SESv2Client({
    region: process.env.AWS_REGION || 'ap-south-1',
    credentials: {
        accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID || 'AKIAT4YSUMZD755UHGW7',
        secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY || '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'
    }
});

// --- 3. HELPER FUNCTIONS ---

// Send Email via SES (Updated Logic)
async function sendEmail(to, subject, htmlContent) {
    const toAddresses = Array.isArray(to) ? to : to.split(',').map(e => e.trim());

    const params = {
        FromEmailAddress: '"LAKSHYA 2K26" <support@testify-lac.com>', 
        Destination: { ToAddresses: toAddresses },
        Content: {
            Simple: {
                Subject: { Data: subject, Charset: 'UTF-8' },
                Body: { Html: { Data: htmlContent, Charset: 'UTF-8' } },
            },
        },
    };

    try {
        const command = new SendEmailCommand(params);
        await sesClient.send(command);
        return true;
    } catch (error) {
        console.error('Error sending email with SES:', error);
        return false;
    }
}

// Middleware to check Authentication
const isAuthenticated = (role) => (req, res, next) => {
    if (req.session.user && req.session.user.role === role) {
        return next();
    }
    res.redirect('/login');
};

// --- 4. ROUTES: PUBLIC PAGES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/static/index.html')));
app.get('/home', (req, res) => res.sendFile(path.join(__dirname, 'public/static/home.html')));
app.get('/launch', (req, res) => res.sendFile(path.join(__dirname, 'public/static/launch.html')));
app.get('/intro', (req, res) => res.sendFile(path.join(__dirname, 'public/static/index.html')));

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/static/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/static/register.html')));
app.get('/events', (req, res) => res.sendFile(path.join(__dirname, 'public/static/events.html')));
app.get('/culturals', (req, res) => res.sendFile(path.join(__dirname, 'public/static/culturals.html')));
app.get('/brochure', (req, res) => res.sendFile(path.join(__dirname, 'public/static/brochure.html')));
app.get('/committee', (req, res) => res.sendFile(path.join(__dirname, 'public/static/committee.html')));
app.get('/contact', (req, res) => res.sendFile(path.join(__dirname, 'public/static/contact.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'public/static/about.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public/static/terms&conditions.html')));
app.get('/get-sponsors', (req, res) => res.sendFile(path.join(__dirname, 'public/static/sponsors.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public/static/privacy.html')));
app.get('/refunds', (req, res) => res.sendFile(path.join(__dirname, 'public/static/refunds.html')));

// --- 5. ROUTES: PARTICIPANT (PROTECTED) ---
app.get('/participant/dashboard', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/dashboard.html'));
});
app.get('/participant/events', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/events.html'));
});
app.get('/participant/cart', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/cart.html'));
});
app.get('/participant/my-registrations', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/my-registrations.html'));
});
app.get('/participant/certificates', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/certificates.html'));
});
app.get('/participant/feedback', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/feedback.html'));
});
app.get('/participant/culturals', isAuthenticated('participant'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/participant/culturals.html'));
});

// --- 6. ROUTES: COORDINATOR (PROTECTED) ---
app.get('/coordinator/dashboard', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/dashboard.html'));
});
app.get('/coordinator/attendance', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/attendance.html'));
});
app.get('/coordinator/payment-status', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/payments.html'));
});
app.get('/coordinator/assign-score', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/assign-score.html'));
});
app.get('/coordinator/registrations', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/registrations.html'));
});
app.get('/coordinator/view-submissions', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/submissions.html'));
});
app.get('/coordinator/event-control', isAuthenticated('coordinator'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/coordinator/event-control.html'));
});

// --- 7. ROUTES: ADMIN (PROTECTED) ---
app.get('/admin/dashboard', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/dashboard.html'));
});
app.get('/admin/add-event', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/add-event.html'));
});
app.get('/admin/manage-users', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/manage-users.html'));
});
app.get('/admin/committee', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/committee.html'));
});
app.get('/admin/departments', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/departments.html'));
});
app.get('/admin/setup-scoring', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/setup-scoring.html'));
});
app.get('/admin/view-scores', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/view-scores.html'));
});
app.get('/admin/manage-events', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/manage-events.html'));
});
app.get('/admin/manage-scoring', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/manage-scoring.html'));
});
app.get('/admin/coupons', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/coupons.html'));
});
app.get('/admin/registrations', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/registrations.html'));
});


// --- 8. API ROUTES: AUTHENTICATION ---
app.post('/api/auth/register', async (req, res) => {
    const { fullName, rollNo, email, mobile, college, password, stream, dept, year } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const params = {
        TableName: 'Lakshya_Users',
        Item: {
            email: email, role: 'participant', fullName, rollNo, mobile, college, stream, dept, year,
            password: hashedPassword, createdAt: new Date().toISOString()
        }
    };
    try { await docClient.send(new PutCommand(params)); res.status(200).json({ message: 'Registration successful' }); }
    catch (err) { res.status(500).json({ error: 'Registration failed', details: err }); }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password, role } = req.body;
    const params = { TableName: 'Lakshya_Users', Key: { email } };
    try {
        const data = await docClient.send(new GetCommand(params));
        const user = data.Item;
        if (!user || user.role !== role) return res.status(401).json({ error: 'Invalid credentials' });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid password' });

        req.session.user = { 
            email: user.email, 
            role: user.role, 
            name: user.fullName,
            dept: user.dept,
            managedEventId: user.managedEventId || null 
        };
        
        res.status(200).json({ message: 'Login successful' });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/auth/send-otp', async (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    req.session.otp = otp;
    
    // HTML Template (kept same)
    const htmlContent = `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f4f4f4; padding: 20px;">
        <div style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
            <div style="background-color: #00d2ff; padding: 20px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 1px;">LAKSHYA 2K26</h1>
            </div>
            <div style="padding: 30px; text-align: center;">
                <h2 style="color: #333333; margin-top: 0;">Verify Your Email</h2>
                <div style="margin: 30px 0;">
                    <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #00d2ff; background-color: #f0faff; padding: 15px 30px; border-radius: 5px; border: 1px dashed #00d2ff;">
                        ${otp}
                    </span>
                </div>
            </div>
        </div>
    </div>`;

    try {
        await sendEmail(email, "LAKSHYA 2K26 - Email Verification", htmlContent);
        res.json({ message: 'OTP sent', debug_otp: otp });
    } catch (e) {
        console.error("OTP Error:", e);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});


// --- 9. API ROUTES: MOCKED PAYMENT & REGISTRATION ---
app.post('/api/register-event', isAuthenticated('participant'), async (req, res) => {
    const { eventId, deptName, paymentMode, teamName, teamMembers, submissionTitle, submissionAbstract, submissionUrl } = req.body;
    const user = req.session.user;

    // CHECK: IS REGISTRATION OPEN FOR THIS DEPT?
    try {
        const statusId = `${eventId}#${deptName}`;
        const statusRes = await docClient.send(new GetCommand({
            TableName: 'Lakshya_EventStatus',
            Key: { statusId }
        }));
        if (statusRes.Item && statusRes.Item.isOpen === false) {
            return res.status(403).json({ error: `Registrations for this event are currently closed by the ${deptName} department.` });
        }
    } catch (e) { console.warn("Status check skipped"); }

    try {
        const checkParams = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'StudentIndex',
            KeyConditionExpression: 'studentEmail = :email',
            FilterExpression: 'eventId = :eid AND deptName = :dept',
            ExpressionAttributeValues: { ':email': user.email, ':eid': eventId, ':dept': deptName }
        };
        const existing = await docClient.send(new QueryCommand(checkParams));
        
        if (existing.Items && existing.Items.length > 0) {
            const existingReg = existing.Items[0];
            
            // IF PAID: Block the request
            if (existingReg.paymentStatus === 'COMPLETED') {
                return res.status(400).json({ error: `You are already registered for this event in the ${deptName} department.` });
            }

            // IF PENDING: Update the existing record with new details and allow proceeding
            try {
                await docClient.send(new UpdateCommand({
                    TableName: 'Lakshya_Registrations',
                    Key: { registrationId: existingReg.registrationId },
                    UpdateExpression: "set teamName = :tn, teamMembers = :tm, submissionTitle = :st, submissionAbstract = :sa, submissionUrl = :su, paymentMode = :pm, registeredAt = :now",
                    ExpressionAttributeValues: {
                        ':tn': teamName || null,
                        ':tm': teamMembers || [],
                        ':st': submissionTitle || null,
                        ':sa': submissionAbstract || null,
                        ':su': submissionUrl || null,
                        ':pm': paymentMode,
                        ':now': new Date().toISOString()
                    }
                }));
                // Return success with EXISTING ID
                return res.json({ message: 'Registration updated', registrationId: existingReg.registrationId });
            } catch (updateErr) {
                console.error(updateErr);
                return res.status(500).json({ error: 'Failed to update pending registration.' });
            }
        }
    } catch (e) {
        return res.status(500).json({ error: 'Server validation failed' });
    }

    // Get Event Title
    let eventTitle = eventId; 
    try {
        const eventRes = await docClient.send(new GetCommand({ TableName: 'Lakshya_Events', Key: { eventId } }));
        if (eventRes.Item) eventTitle = eventRes.Item.title;
    } catch (e) {}

    const registrationId = uuidv4();
    const paymentStatus = 'PENDING'; 

    const params = {
        TableName: 'Lakshya_Registrations',
        Item: {
            registrationId,
            studentEmail: user.email,
            eventId,
            deptName,
            teamName: teamName || null, 
            teamMembers: teamMembers || [],
            submissionTitle: submissionTitle || null,
            submissionAbstract: submissionAbstract || null,
            submissionUrl: submissionUrl || null,
            paymentStatus: paymentStatus,
            paymentMode, 
            attendance: false,
            registeredAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        
        // --- MODIFIED EMAIL LOGIC ---
        // Only send "Pending" email if mode is NOT Online. 
        // If Online, we wait for payment/verify to send the "Completed" email.
        if (paymentMode !== 'Online') {
            const subject = `Registration Confirmed: ${eventTitle}`;
            const emailBody = `
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
                    <h2 style="color: #00d2ff;">LAKSHYA 2K26</h2>
                    <p>Dear Participant,</p>
                    <p>Thank you for registering for <strong>${eventTitle}</strong>.</p>
                    <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                        <p><strong>Registration ID:</strong> ${registrationId}</p>
                        <p><strong>Event:</strong> ${eventTitle}</p>
                        <p><strong>Payment Status:</strong> <span style="color: orange; font-weight: bold;">PAYMENT PENDING (Pay at Venue)</span></p>
                    </div>
                    <p>Best Regards,<br>Team LAKSHYA</p>
                </div>`;
            
            await sendEmail(user.email, subject, emailBody);

            if (teamMembers && Array.isArray(teamMembers)) {
                teamMembers.filter(m => m.email).forEach(m => sendEmail(m.email, subject, emailBody));
            }
        }

        res.json({ message: 'Registration initiated', registrationId });
    } catch (err) {
        res.status(500).json({ error: 'Registration failed' });
    }
});
// Create Order (Razorpay)
// Create Order (Razorpay)
app.post('/api/payment/create-order', isAuthenticated('participant'), async (req, res) => {
    const { amount, couponCode } = req.body;
    let baseAmount = amount; 
    let couponApplied = false;

    if (couponCode) {
        try {
            const couponRes = await docClient.send(new GetCommand({
                TableName: 'Lakshya_Coupons', Key: { code: couponCode.toUpperCase() }
            }));
            const coupon = couponRes.Item;
            if (coupon && coupon.usedCount < coupon.usageLimit) {
                const discount = (baseAmount * coupon.percentage) / 100;
                baseAmount = Math.round(baseAmount - discount);
                couponApplied = true;
            }
        } catch (e) {}
    }

    if (baseAmount < 1) baseAmount = 1;
    const platformFee = Math.ceil(baseAmount * 0.0236); 
    const totalAmount = baseAmount + platformFee;

    const options = {
        amount: totalAmount * 100, // paise
        currency: "INR",
        receipt: "receipt_" + uuidv4().substring(0, 10),
        notes: { couponCode: couponCode || "NONE", fee: platformFee, base: baseAmount }
    };

    try {
        const order = await razorpay.orders.create(options);
        if (couponApplied) {
            await docClient.send(new UpdateCommand({
                TableName: 'Lakshya_Coupons', Key: { code: couponCode.toUpperCase() },
                UpdateExpression: "set usedCount = usedCount + :inc",
                ExpressionAttributeValues: { ":inc": 1 }
            }));
        }
        // FIX IS HERE: Use RAZORPAY_KEY_ID variable instead of process.env directly
        res.json({ id: order.id, amount: order.amount, currency: order.currency, key_id: RAZORPAY_KEY_ID });
    } catch (err) {
        console.error("Order creation failed:", err);
        res.status(500).json({ error: "Order creation failed" });
    }
});
// Payment Verification
app.post('/api/payment/verify', isAuthenticated('participant'), async (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, registrationIds, couponCode, registrationAmounts } = req.body;
    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body.toString()).digest('hex');

    if (expectedSignature === razorpay_signature) {
        try {
            if (registrationIds && Array.isArray(registrationIds)) {
                // 1. CRITICAL: Update Database Status FIRST (Wait for this)
                const updatePromises = registrationIds.map(regId => {
                    const paidAmt = (registrationAmounts && registrationAmounts[regId]) ? parseFloat(registrationAmounts[regId]) : 0;
                    return docClient.send(new UpdateCommand({
                        TableName: 'Lakshya_Registrations', Key: { registrationId: regId },
                        UpdateExpression: "set paymentStatus = :s, paymentId = :p, paymentMode = :m, attendance = :a, couponUsed = :c, paymentDate = :d, amountPaid = :amt",
                        ExpressionAttributeValues: {
                            ":s": "COMPLETED", ":p": razorpay_payment_id, ":m": "ONLINE", ":a": false,
                            ":c": couponCode || "NONE", ":d": new Date().toISOString(), ":amt": paidAmt 
                        }
                    }));
                });
                await Promise.all(updatePromises);

                // 2. CRITICAL FIX: Send Success Response IMMEDIATELY to prevent 504 Timeout
                res.json({ status: 'success' });

                // 3. Send Emails in BACKGROUND (Do NOT await, do NOT block response)
                // This runs asynchronously after the response is sent.
                (async () => {
                    for (const regId of registrationIds) {
                        try {
                            const regData = await docClient.send(new GetCommand({ TableName: 'Lakshya_Registrations', Key: { registrationId: regId } }));
                            const reg = regData.Item;
                            if (!reg) continue;

                            const eventData = await docClient.send(new GetCommand({ TableName: 'Lakshya_Events', Key: { eventId: reg.eventId } }));
                            const eventTitle = eventData.Item ? eventData.Item.title : "Event";

                            // --- MAIL 1: REGISTRATION CONFIRMATION ---
                            const regSubject = `Registration Confirmed: ${eventTitle}`;
                            const regBody = `
                                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
                                    <h2 style="color: #00d2ff;">LAKSHYA 2K26</h2>
                                    <p>Dear Participant,</p>
                                    <p>Thank you for registering for <strong>${eventTitle}</strong>. Your registration is now confirmed.</p>
                                    <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                        <p><strong>Registration ID:</strong> ${regId}</p>
                                        <p><strong>Event:</strong> ${eventTitle}</p>
                                        <p><strong>Team:</strong> ${reg.teamName || 'Individual'}</p>
                                        <p><strong>Payment Status:</strong> <span style="color: green; font-weight: bold;">COMPLETED</span></p>
                                    </div>
                                    <p>Best Regards,<br>Team LAKSHYA</p>
                                </div>`;
                            
                            // Fire and forget individual emails to avoid blocking
                            sendEmail(reg.studentEmail, regSubject, regBody).catch(e => console.error("Email Fail", e));
                            
                            if (reg.teamMembers && Array.isArray(reg.teamMembers)) {
                                 reg.teamMembers.filter(m => m.email).forEach(m => {
                                     sendEmail(m.email, regSubject, regBody).catch(e => console.error("Team Email Fail", e));
                                 });
                            }

                            // --- MAIL 2: PAYMENT RECEIPT ---
                            const paySubject = `Payment Receipt: ${eventTitle}`;
                            const paidAmt = (registrationAmounts && registrationAmounts[regId]) ? registrationAmounts[regId] : 'N/A';
                            const payBody = `
                                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
                                    <h2 style="color: #4CAF50;">Payment Successful</h2>
                                    <p>Dear Participant,</p>
                                    <p>We have successfully received your payment for <strong>${eventTitle}</strong>.</p>
                                    <div style="background: #f0fff4; padding: 15px; border-radius: 5px; margin: 15px 0; border: 1px solid #c3e6cb;">
                                        <p><strong>Transaction ID:</strong> ${razorpay_payment_id}</p>
                                        <p><strong>Amount Paid:</strong> ₹${paidAmt}</p>
                                        <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
                                        <p><strong>Payment Mode:</strong> Online (Razorpay)</p>
                                    </div>
                                    <p>Please keep this receipt for your records.</p>
                                    <p>Best Regards,<br>Team LAKSHYA</p>
                                </div>`;
                            
                            sendEmail(reg.studentEmail, paySubject, payBody).catch(e => console.error("Receipt Email Fail", e));

                        } catch (innerErr) {
                            console.error("Background Email Error for regId: " + regId, innerErr);
                        }
                    }
                })(); 
            } else {
                 // No registration IDs? Still return success if signature matched to avoid user panic, but log error.
                 res.json({ status: 'success', warning: 'No reg IDs found' });
            }
        } catch (err) {
            console.error("DB Update Error:", err);
            // If DB update fails, we MUST tell the frontend
            res.status(500).json({ error: 'DB update failed' });
        }
    } else {
        res.status(400).json({ error: 'Invalid signature' });
    }
});

app.get('/api/participant/dashboard-stats', isAuthenticated('participant'), async (req, res) => {
    const userEmail = req.session.user.email;
    try {
        const userRes = await docClient.send(new GetCommand({ TableName: 'Lakshya_Users', Key: { email: userEmail } }));
        const userDetails = userRes.Item || {};

        const data = await docClient.send(new QueryCommand({
            TableName: 'Lakshya_Registrations', IndexName: 'StudentIndex',
            KeyConditionExpression: 'studentEmail = :email',
            ExpressionAttributeValues: { ':email': userEmail }
        }));
        
        const registrations = data.Items || [];
        const total = registrations.length;
        const paid = registrations.filter(r => r.paymentStatus === 'COMPLETED').length;
        let status = total > 0 ? (paid === total ? 'Paid' : (paid > 0 ? 'Partial' : 'Pending')) : 'None';

        res.json({
            name: userDetails.fullName || req.session.user.name,
            rollNo: userDetails.rollNo || '-',
            college: userDetails.college || '',
            mobile: userDetails.mobile || '',
            totalRegistrations: total,
            paymentStatus: status
        });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/participant/my-registrations-data', isAuthenticated('participant'), async (req, res) => {
    const userEmail = req.session.user.email;
    try {
        const data = await docClient.send(new QueryCommand({
            TableName: 'Lakshya_Registrations', IndexName: 'StudentIndex',
            KeyConditionExpression: 'studentEmail = :email',
            ExpressionAttributeValues: { ':email': userEmail }
        }));
        res.json(data.Items);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});


// =========================================================
//  --- COORDINATOR API ROUTES (FIXED & CONSOLIDATED) ---
// =========================================================

// 1. Get Dashboard Data (Handles Specific Event Coordinators vs Dept Coordinators)
app.get('/api/coordinator/dashboard-data', isAuthenticated('coordinator'), async (req, res) => {
    try {
        const user = req.session.user;
        const userDept = user.dept;
        const managedEventId = user.managedEventId;

        // SCENARIO 1: Specific Event Coordinator
        if (managedEventId) {
            // FIX: Use SCAN to find registrations for this event across ALL departments
            const params = {
                TableName: 'Lakshya_Registrations',
                FilterExpression: 'eventId = :eid',
                ExpressionAttributeValues: { ':eid': managedEventId }
            };
            const data = await docClient.send(new ScanCommand(params));
            return res.json({ 
                dept: `Event: ${managedEventId}`, 
                registrations: data.Items || [] 
            });
        }

        // SCENARIO 2: Department Coordinator
        if (!userDept) return res.json({ dept: 'Unknown', registrations: [] });
        
        const params = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'DepartmentIndex',
            KeyConditionExpression: 'deptName = :dept',
            ExpressionAttributeValues: { ':dept': userDept }
        };
        const data = await docClient.send(new QueryCommand(params));
        res.json({ dept: userDept, registrations: data.Items || [] });

    } catch (err) {
        console.error("Coord Dashboard Error:", err);
        res.status(500).json({ error: 'Failed to load data' });
    }
});

// 2. Get Events List (My Events)
app.get('/api/coordinator/my-events', isAuthenticated('coordinator'), async (req, res) => {
    // If specific event coordinator, return ONLY that event
    if(req.session.user.managedEventId) {
        try {
            const data = await docClient.send(new GetCommand({ 
                TableName: 'Lakshya_Events', 
                Key: { eventId: req.session.user.managedEventId } 
            }));
            return res.json(data.Item ? [data.Item] : []);
        } catch(e) { return res.json([]); }
    }

    // Else return all events for the dept
    const userDept = req.session.user.dept;
    if (!userDept) return res.json([]);
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        const allEvents = data.Items || [];
        const myEvents = allEvents.filter(e => e.departments && e.departments.includes(userDept));
        res.json(myEvents);
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// 3. Get Students for Attendance (FIXED for Specific Event Coordinators)
app.get('/api/coordinator/event-students', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId } = req.query;
    const user = req.session.user;
    const managedEventId = user.managedEventId;

    try {
        let items = [];

        // If Specific Event Coordinator: Force usage of managedEventId
        if (managedEventId) {
            // Security check: Ensure they are asking for their own event
            if(eventId && eventId !== managedEventId) {
                 return res.json([]); 
            }
            
            // Scan filtering by EventID + Paid Status (Across all depts)
            const params = {
                TableName: 'Lakshya_Registrations',
                FilterExpression: 'eventId = :eid AND paymentStatus = :paid',
                ExpressionAttributeValues: {
                    ':eid': managedEventId,
                    ':paid': 'COMPLETED'
                }
            };
            const data = await docClient.send(new ScanCommand(params));
            items = data.Items || [];
        } 
        else {
            // Regular Dept Coordinator: Query by Dept
            const params = {
                TableName: 'Lakshya_Registrations',
                IndexName: 'DepartmentIndex',
                KeyConditionExpression: 'deptName = :dept',
                FilterExpression: 'eventId = :eid AND paymentStatus = :paid',
                ExpressionAttributeValues: {
                    ':dept': user.dept,
                    ':eid': eventId,
                    ':paid': 'COMPLETED'
                }
            };
            const data = await docClient.send(new QueryCommand(params));
            items = data.Items || [];
        }

        res.json(items);
    } catch(e) {
        console.error("Event Students Error:", e);
        res.status(500).json({ error: 'Failed to fetch students' });
    }
});

// 4. Pending Payments (FIXED for Specific Event Coordinators)
app.get('/api/coordinator/pending-payments', isAuthenticated('coordinator'), async (req, res) => {
    try {
        const user = req.session.user;
        const managedEventId = user.managedEventId;
        let items = [];

        if (managedEventId) {
            // Specific Event Coordinator: Scan by EventID, NOT Completed
            const params = {
                TableName: 'Lakshya_Registrations',
                FilterExpression: 'eventId = :eid AND paymentStatus <> :paid',
                ExpressionAttributeValues: {
                    ':eid': managedEventId,
                    ':paid': 'COMPLETED'
                }
            };
            const data = await docClient.send(new ScanCommand(params));
            items = data.Items || [];
        } else {
            // Dept Coordinator: Query by Dept, NOT Completed
            const params = {
                TableName: 'Lakshya_Registrations',
                IndexName: 'DepartmentIndex',
                KeyConditionExpression: 'deptName = :dept',
                FilterExpression: 'paymentStatus <> :paid',
                ExpressionAttributeValues: {
                    ':dept': user.dept,
                    ':paid': 'COMPLETED'
                }
            };
            const data = await docClient.send(new QueryCommand(params));
            items = data.Items || [];
        }

        res.json(items);
    } catch (err) {
        console.error("Pending Payments Error:", err);
        res.status(500).json({ error: 'Failed to fetch data' });
    }
});

// 5. Quick Attendance (Lookup)
app.post('/api/coordinator/quick-attendance', isAuthenticated('coordinator'), async (req, res) => {
    const { identifier } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId: identifier },
        UpdateExpression: "set attendance = :a",
        ExpressionAttributeValues: { ":a": true },
        ReturnValues: "ALL_NEW"
    };
    try {
        const data = await docClient.send(new UpdateCommand(params));
        if (data.Attributes) {
            res.json({ message: 'Success', studentEmail: data.Attributes.studentEmail, eventId: data.Attributes.eventId });
        } else {
            res.status(404).json({ error: 'Registration ID not found' });
        }
    } catch (err) { res.status(500).json({ error: 'Lookup failed' }); }
});

// 6. Mark Attendance
app.post('/api/coordinator/mark-attendance', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId, status } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations', Key: { registrationId },
        UpdateExpression: "set attendance = :a", ExpressionAttributeValues: { ":a": status }
    };
    try { await docClient.send(new UpdateCommand(params)); res.json({ message: 'Attendance updated' }); }
    catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

// 7. Mark Paid
app.post('/api/coordinator/mark-paid', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations', Key: { registrationId },
        UpdateExpression: "set paymentStatus = :s, paymentMode = :m",
        ExpressionAttributeValues: { ":s": "COMPLETED", ":m": "CASH" }
    };
    try { await docClient.send(new UpdateCommand(params)); res.json({ message: 'Payment marked as received' }); }
    catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

// 8. Fetch Student Details (No changes needed)
app.get('/api/coordinator/student-details', isAuthenticated('coordinator'), async (req, res) => {
    const { email } = req.query;
    try {
        const data = await docClient.send(new GetCommand({ TableName: 'Lakshya_Users', Key: { email } }));
        if (data.Item) {
            const { password, ...studentData } = data.Item;
            res.json(studentData);
        } else { res.status(404).json({ error: 'Student not found' }); }
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// 9. Export Bulk Data
app.post('/api/coordinator/export-data', isAuthenticated('coordinator'), async (req, res) => {
    const { emails } = req.body; 
    if (!emails || !Array.isArray(emails) || emails.length === 0) return res.json({});
    const uniqueEmails = [...new Set(emails)];

    try {
        const userPromises = uniqueEmails.map(email => 
            docClient.send(new GetCommand({
                TableName: 'Lakshya_Users', Key: { email },
                ProjectionExpression: 'email, fullName, rollNo, dept, mobile, #y, college',
                ExpressionAttributeNames: { "#y": "year" } 
            }))
        );
        const results = await Promise.all(userPromises);
        const userMap = {};
        results.forEach(r => { if (r.Item) userMap[r.Item.email] = r.Item; });
        res.json(userMap);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// 10. Scoring Details
app.get('/api/coordinator/scoring-details', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId } = req.query;
    const user = req.session.user;
    const deptName = user.dept; // For scheme ID, we might need adjustments if event ID coordinator

    // Assumption: Specific event coordinators still use a specific dept name for the scheme
    // OR the scheme ID should just use the eventId if deptName is irrelevant.
    // Keeping logic simple: Use session dept. If managedEventId, maybe use 'General' or default?
    
    // Fallback: If managedEventId, we might not have a dept. 
    // BUT usually scoring schemes are dept specific. 
    // If specific event coord, we assume they access the scheme defined for that event.
    
    // For now, retaining existing logic but adding null check
    if (!eventId || (!deptName && !user.managedEventId)) return res.status(400).json({ error: "Missing params" });

    try {
        // A. Fetch Scheme
        // Use deptName if available, else maybe default. 
        // NOTE: If Specific Event Coord doesn't have a dept, they might not be able to CREATE a scheme properly
        // without this. Assuming Admin created it.
        const effectiveDept = deptName || "General"; 
        const schemeId = `${eventId}#${effectiveDept}`;
        
        const schemeRes = await docClient.send(new GetCommand({
            TableName: 'Lakshya_ScoringSchemes', Key: { schemeId }
        }));
        const scheme = schemeRes.Item;
        if (!scheme) return res.json({ enabled: false, message: "Scoring not configured." });

        // B. Fetch Students (PRESENT only)
        // Similar logic to event-students, need to handle managedEventId
        let students = [];
        if (user.managedEventId) {
             const params = {
                TableName: 'Lakshya_Registrations',
                FilterExpression: 'eventId = :eid AND attendance = :att',
                ExpressionAttributeValues: { ':eid': user.managedEventId, ':att': true }
             };
             const data = await docClient.send(new ScanCommand(params));
             students = data.Items || [];
        } else {
             const params = {
                TableName: 'Lakshya_Registrations',
                IndexName: 'DepartmentIndex',
                KeyConditionExpression: 'deptName = :dept',
                FilterExpression: 'eventId = :eid AND attendance = :att', 
                ExpressionAttributeValues: { ':dept': deptName, ':eid': eventId, ':att': true }
            };
            const data = await docClient.send(new QueryCommand(params));
            students = data.Items || [];
        }

        res.json({
            enabled: true,
            scheme: scheme.criteria,
            isLocked: scheme.isLocked === true,
            students: students.map(s => ({
                registrationId: s.registrationId,
                studentEmail: s.studentEmail,
                totalScore: s.totalScore || 0,
                scoreBreakdown: s.scoreBreakdown || {}, 
                teamName: s.teamName, // Added team name passthrough
                teamMembers: s.teamMembers // Added members passthrough
            }))
        });
    } catch (err) { res.status(500).json({ error: "Failed to load scoring data" }); }
});

// 11. Submit Scores
app.post('/api/coordinator/submit-scores', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId, scores, finalize } = req.body; 
    const deptName = req.session.user.dept || "General"; 

    try {
        const updatePromises = scores.map(student => {
            return docClient.send(new UpdateCommand({
                TableName: 'Lakshya_Registrations',
                Key: { registrationId: student.registrationId },
                UpdateExpression: "set scoreBreakdown = :sb, totalScore = :ts",
                ExpressionAttributeValues: { ":sb": student.breakdown, ":ts": student.total }
            }));
        });
        await Promise.all(updatePromises);

        if (finalize) {
            const schemeId = `${eventId}#${deptName}`;
            await docClient.send(new UpdateCommand({
                TableName: 'Lakshya_ScoringSchemes', Key: { schemeId },
                UpdateExpression: "set isLocked = :l", ExpressionAttributeValues: { ":l": true }
            }));
        }
        res.json({ message: finalize ? "Locked" : "Saved" });
    } catch (err) { res.status(500).json({ error: "Failed" }); }
});

// 12. View Submissions
app.get('/api/coordinator/submissions', isAuthenticated('coordinator'), async (req, res) => {
    const user = req.session.user;
    try {
        let items = [];
        if (user.managedEventId) {
             const params = {
                TableName: 'Lakshya_Registrations',
                FilterExpression: 'eventId = :eid',
                ExpressionAttributeValues: { ':eid': user.managedEventId }
             };
             const data = await docClient.send(new ScanCommand(params));
             items = data.Items || [];
        } else {
            const params = {
                TableName: 'Lakshya_Registrations',
                IndexName: 'DepartmentIndex',
                KeyConditionExpression: 'deptName = :dept',
                ExpressionAttributeValues: { ':dept': user.dept }
            };
            const data = await docClient.send(new QueryCommand(params));
            items = data.Items || [];
        }
        
        const withSubs = items.filter(r => r.submissionTitle || r.submissionUrl);
        res.json(withSubs);
    } catch (err) { res.status(500).json({ error: "Failed" }); }
});

// 13. Event Control
app.get('/api/coordinator/event-controls', isAuthenticated('coordinator'), async (req, res) => {
    const user = req.session.user;
    try {
        // For Event Control, if specific event coord, just return their one event
        let myEvents = [];
        if (user.managedEventId) {
             const e = await docClient.send(new GetCommand({ TableName: 'Lakshya_Events', Key: { eventId: user.managedEventId }}));
             if(e.Item) myEvents.push(e.Item);
        } else {
             const eventData = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
             myEvents = (eventData.Items || []).filter(e => e.departments && e.departments.includes(user.dept));
        }

        const statusData = await docClient.send(new ScanCommand({ TableName: 'Lakshya_EventStatus' }));
        const statusMap = {};
        (statusData.Items || []).forEach(s => {
            if (s.deptName === user.dept || user.managedEventId) statusMap[s.eventId] = s.isOpen;
        });

        const result = myEvents.map(e => ({
            eventId: e.eventId, title: e.title,
            isOpen: statusMap[e.eventId] !== false 
        }));
        res.json(result);
    } catch (e) { res.status(500).json({ error: "Failed" }); }
});

app.post('/api/coordinator/toggle-event', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId, isOpen } = req.body;
    const userDept = req.session.user.dept || "General";
    const statusId = `${eventId}#${userDept}`;
    const params = {
        TableName: 'Lakshya_EventStatus',
        Item: { statusId, eventId, deptName: userDept, isOpen, updatedAt: new Date().toISOString() }
    };
    try { await docClient.send(new PutCommand(params)); res.json({ message: 'Updated' }); }
    catch (e) { res.status(500).json({ error: "Update failed" }); }
});

// ===============================================
// --- ADMIN ROUTES (KEEPING AS IS) ---
// ===============================================

app.get('/api/admin/stats', isAuthenticated('admin'), async (req, res) => {
    try {
        const [users, events, regs] = await Promise.all([
            docClient.send(new ScanCommand({ TableName: 'Lakshya_Users', Select: 'COUNT' })),
            docClient.send(new ScanCommand({ TableName: 'Lakshya_Events', Select: 'COUNT' })),
            docClient.send(new ScanCommand({ TableName: 'Lakshya_Registrations' }))
        ]);
        const registrations = regs.Items || [];
        const totalRevenue = registrations.reduce((sum, r) => r.paymentStatus === 'COMPLETED' ? sum + 200 : sum, 0);
        const deptCounts = {};
        registrations.forEach(r => { const d = r.deptName || 'General'; deptCounts[d] = (deptCounts[d] || 0) + 1; });
        const paymentCounts = { Paid: 0, Pending: 0 };
        registrations.forEach(r => r.paymentStatus === 'COMPLETED' ? paymentCounts.Paid++ : paymentCounts.Pending++);

        res.json({
            totalUsers: users.Count, totalEvents: events.Count, totalRegistrations: regs.Count,
            totalRevenue, deptCounts, paymentCounts
        });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/student-details', isAuthenticated('admin'), async (req, res) => {
    const { email } = req.query;
    try {
        const data = await docClient.send(new GetCommand({ TableName: 'Lakshya_Users', Key: { email } }));
        if (data.Item) { const { password, ...d } = data.Item; res.json(d); }
        else res.status(404).json({ error: 'Not found' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/all-registrations', isAuthenticated('admin'), async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Registrations' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/create-user', isAuthenticated('admin'), async (req, res) => {
    const { email, password, role, fullName, dept } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const params = {
        TableName: 'Lakshya_Users',
        Item: { email, role, fullName, dept, password: hashedPassword, createdAt: new Date().toISOString() }
    };
    try { await docClient.send(new PutCommand(params)); res.json({ message: 'User created' }); }
    catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/departments', async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Departments' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/add-event', isAuthenticated('admin'), upload.single('image'), async (req, res) => {
    try {
        const { title, type, description, teamSize, fee, departments, sections } = req.body;
        let imageUrl = 'default.jpg';
        if (req.file) {
            const fileName = `events/${uuidv4()}-${req.file.originalname}`;
            const uploadParams = {
                Bucket: 'hirewithusjobapplications', Key: fileName,
                Body: req.file.buffer, ContentType: req.file.mimetype
            };
            await s3Client.send(new PutObjectCommand(uploadParams));
            imageUrl = `https://hirewithusjobapplications.s3.ap-south-1.amazonaws.com/${fileName}`;
        }
        const eventId = uuidv4();
        const params = {
            TableName: 'Lakshya_Events',
            Item: {
                eventId, title, type, description, teamSize, fee,
                departments: JSON.parse(departments), sections: JSON.parse(sections),
                imageUrl, createdAt: new Date().toISOString()
            }
        };
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Event created' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/add-department', isAuthenticated('admin'), async (req, res) => {
    const { name } = req.body;
    try {
        await docClient.send(new PutCommand({
            TableName: 'Lakshya_Departments',
            Item: { deptId: uuidv4(), name: name.toUpperCase(), createdAt: new Date().toISOString() }
        }));
        res.json({ message: 'Added' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/delete-department', isAuthenticated('admin'), async (req, res) => {
    try {
        await docClient.send(new DeleteCommand({ TableName: 'Lakshya_Departments', Key: { deptId: req.body.deptId } }));
        res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/events', async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/save-scheme', isAuthenticated('admin'), async (req, res) => {
    const { eventId, deptName, criteria } = req.body;
    const schemeId = `${eventId}#${deptName}`;
    const params = {
        TableName: 'Lakshya_ScoringSchemes',
        Item: { schemeId, eventId, deptName, criteria: JSON.parse(criteria), isLocked: false, updatedAt: new Date().toISOString() },
        ConditionExpression: 'attribute_not_exists(schemeId)'
    };
    try { await docClient.send(new PutCommand(params)); res.json({ message: 'Saved' }); }
    catch (err) { res.status(400).json({ error: 'Already exists' }); }
});

app.get('/api/admin/all-schemes', isAuthenticated('admin'), async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_ScoringSchemes' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/update-scheme', isAuthenticated('admin'), async (req, res) => {
    const { schemeId, criteria, isLocked } = req.body;
    const params = {
        TableName: 'Lakshya_ScoringSchemes', Key: { schemeId },
        UpdateExpression: "set criteria = :c, isLocked = :l, updatedAt = :u",
        ExpressionAttributeValues: { ":c": JSON.parse(criteria), ":l": isLocked, ":u": new Date().toISOString() }
    };
    try { await docClient.send(new UpdateCommand(params)); res.json({ message: 'Updated' }); }
    catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/delete-scheme', isAuthenticated('admin'), async (req, res) => {
    try {
        await docClient.send(new DeleteCommand({ TableName: 'Lakshya_ScoringSchemes', Key: { schemeId: req.body.schemeId } }));
        res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// Utility Cart Endpoints
app.get('/api/cart', isAuthenticated('participant'), async (req, res) => {
    try {
        const data = await docClient.send(new GetCommand({ TableName: 'Lakshya_Cart', Key: { email: req.session.user.email } }));
        res.json(data.Item ? data.Item.items : []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});
app.post('/api/cart', isAuthenticated('participant'), async (req, res) => {
    try {
        await docClient.send(new PutCommand({
            TableName: 'Lakshya_Cart',
            Item: { email: req.session.user.email, items: req.body.items, updatedAt: new Date().toISOString() }
        }));
        res.json({ message: 'Saved' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});
app.delete('/api/cart', isAuthenticated('participant'), async (req, res) => {
    try {
        await docClient.send(new DeleteCommand({ TableName: 'Lakshya_Cart', Key: { email: req.session.user.email } }));
        res.json({ message: 'Cleared' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/export-data', isAuthenticated('admin'), async (req, res) => {
    const { emails } = req.body;
    if (!emails || !Array.isArray(emails)) return res.json({});
    try {
        const userPromises = [...new Set(emails)].map(email => 
            docClient.send(new GetCommand({
                TableName: 'Lakshya_Users', Key: { email },
                ProjectionExpression: 'email, fullName, mobile, college, rollNo, dept, #y',
                ExpressionAttributeNames: { "#y": "year" }
            }))
        );
        const results = await Promise.all(userPromises);
        const userMap = {};
        results.forEach(r => { if (r.Item) userMap[r.Item.email] = r.Item; });
        res.json(userMap);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/scores', isAuthenticated('admin'), async (req, res) => {
    const { eventId, deptName } = req.query;
    try {
        const scanParams = { TableName: 'Lakshya_Registrations', FilterExpression: 'attribute_exists(totalScore)' };
        const filters = []; const attrValues = {}; const attrNames = {};

        if (eventId && eventId !== 'all') { filters.push('eventId = :eid'); attrValues[':eid'] = eventId; }
        if (deptName && deptName !== 'all') { filters.push('#d = :dn'); attrValues[':dn'] = deptName; attrNames['#d'] = 'deptName'; }

        if (filters.length > 0) {
            scanParams.FilterExpression += ' AND ' + filters.join(' AND ');
            scanParams.ExpressionAttributeValues = attrValues;
            if (Object.keys(attrNames).length > 0) scanParams.ExpressionAttributeNames = attrNames;
        }

        const data = await docClient.send(new ScanCommand(scanParams));
        let items = data.Items || [];
        items.sort((a, b) => parseFloat(b.totalScore) - parseFloat(a.totalScore));
        res.json(items);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/delete-event', isAuthenticated('admin'), async (req, res) => {
    try {
        await docClient.send(new DeleteCommand({ TableName: 'Lakshya_Events', Key: { eventId: req.body.eventId } }));
        res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/update-event', isAuthenticated('admin'), upload.single('image'), async (req, res) => {
    try {
        const { eventId, title, type, description, fee, departments, sections } = req.body;
        let updateExp = "set title=:t, #type=:ty, description=:d, fee=:f, departments=:depts, sections=:sec";
        let expValues = { ':t': title, ':ty': type, ':d': description, ':f': fee, ':depts': JSON.parse(departments), ':sec': JSON.parse(sections) };
        if (req.file) {
            const fileName = `events/${uuidv4()}-${req.file.originalname}`;
            await s3Client.send(new PutObjectCommand({ Bucket: 'hirewithusjobapplications', Key: fileName, Body: req.file.buffer, ContentType: req.file.mimetype }));
            updateExp += ", imageUrl=:img";
            expValues[':img'] = `https://hirewithusjobapplications.s3.ap-south-1.amazonaws.com/${fileName}`;
        }
        await docClient.send(new UpdateCommand({
            TableName: 'Lakshya_Events', Key: { eventId }, UpdateExpression: updateExp, ExpressionAttributeValues: expValues, ExpressionAttributeNames: { "#type": "type" }
        }));
        res.json({ message: 'Updated' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// Committee & Misc
app.post('/api/admin/add-committee-member', isAuthenticated('admin'), upload.single('image'), async (req, res) => {
    try {
        const { name, role, category } = req.body;
        let imageUrl = 'assets/default-user.png';
        if (req.file) {
            const fileName = `committee/${uuidv4()}-${req.file.originalname}`;
            await s3Client.send(new PutObjectCommand({ Bucket: 'hirewithusjobapplications', Key: fileName, Body: req.file.buffer, ContentType: req.file.mimetype }));
            imageUrl = `https://hirewithusjobapplications.s3.ap-south-1.amazonaws.com/${fileName}`;
        }
        await docClient.send(new PutCommand({
            TableName: 'Lakshya_Committee',
            Item: { memberId: uuidv4(), name, role, category, imageUrl, createdAt: new Date().toISOString() }
        }));
        res.json({ message: 'Added' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/committee', async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Committee' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});
app.post('/api/admin/delete-committee-member', isAuthenticated('admin'), async (req, res) => {
    try {
        await docClient.send(new DeleteCommand({ TableName: 'Lakshya_Committee', Key: { memberId: req.body.memberId } }));
        res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/auth/forgot-password-request', async (req, res) => {
    const { email } = req.body;
    try {
        const userCheck = await docClient.send(new GetCommand({ TableName: 'Lakshya_Users', Key: { email } }));
        if (!userCheck.Item) return res.status(404).json({ error: 'Email not registered' });
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await docClient.send(new UpdateCommand({
            TableName: 'Lakshya_Users', Key: { email },
            UpdateExpression: "set resetOtp = :o, resetOtpExp = :e",
            ExpressionAttributeValues: { ":o": otp, ":e": Date.now() + 15 * 60 * 1000 }
        }));
        await sendEmail(email, "LAKSHYA 2K26 - Password Reset OTP", `<p>Your OTP is: <strong>${otp}</strong></p>`);
        res.json({ message: 'OTP sent' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    try {
        const data = await docClient.send(new GetCommand({ TableName: 'Lakshya_Users', Key: { email } }));
        const user = data.Item;
        if (!user || user.resetOtp !== otp || Date.now() > user.resetOtpExp) return res.status(400).json({ error: 'Invalid OTP' });
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await docClient.send(new UpdateCommand({
            TableName: 'Lakshya_Users', Key: { email },
            UpdateExpression: "set password = :p remove resetOtp, resetOtpExp",
            ExpressionAttributeValues: { ":p": hashedPassword }
        }));
        res.json({ message: 'Password reset successfully' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// Coupons
app.post('/api/admin/create-coupon', isAuthenticated('admin'), async (req, res) => {
    const { code, percentage, limit } = req.body;
    try {
        await docClient.send(new PutCommand({
            TableName: 'Lakshya_Coupons',
            Item: { code: code.toUpperCase(), percentage: parseInt(percentage), usageLimit: parseInt(limit), usedCount: 0, createdAt: new Date().toISOString() },
            ConditionExpression: 'attribute_not_exists(code)'
        }));
        res.json({ message: 'Created' });
    } catch (err) { res.status(400).json({ error: 'Failed' }); }
});
app.get('/api/admin/coupons', isAuthenticated('admin'), async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Coupons' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});
app.post('/api/admin/delete-coupon', isAuthenticated('admin'), async (req, res) => {
    try {
        await docClient.send(new DeleteCommand({ TableName: 'Lakshya_Coupons', Key: { code: req.body.code } }));
        res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});
app.post('/api/coupon/validate', isAuthenticated('participant'), async (req, res) => {
    const { code } = req.body;
    try {
        const data = await docClient.send(new GetCommand({ TableName: 'Lakshya_Coupons', Key: { code: code.toUpperCase() } }));
        const coupon = data.Item;
        if (!coupon || coupon.usedCount >= coupon.usageLimit) return res.status(400).json({ error: "Invalid/Expired" });
        res.json({ code: coupon.code, percentage: coupon.percentage, message: "Applied" });
    } catch (err) { res.status(500).json({ error: "Failed" }); }
});

// File Upload Utility
app.post('/api/utility/upload-file', isAuthenticated('participant'), upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file' });
        const fileName = `temp_uploads/${req.session.user.email}_${uuidv4()}.${req.file.originalname.split('.').pop()}`;
        await s3Client.send(new PutObjectCommand({ Bucket: 'hirewithusjobapplications', Key: fileName, Body: req.file.buffer, ContentType: req.file.mimetype }));
        res.json({ url: `https://hirewithusjobapplications.s3.ap-south-1.amazonaws.com/${fileName}` });
    } catch (e) { res.status(500).json({ error: 'Upload failed' }); }
});

// Chatbot & FAQ
app.use('/api/chat', chatRoute);

app.get('/api/culturals', async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        const culturalKeywords = ['cultural', 'music', 'dance', 'singing', 'drama', 'fashion', 'art'];
        const culturalEvents = (data.Items || []).filter(e => {
            const t = (e.type || '').toLowerCase() + (e.title || '').toLowerCase();
            return culturalKeywords.some(key => t.includes(key));
        });
        res.json(culturalEvents);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => { console.log(`Server running on http://localhost:${PORT}`); });
}

module.exports = app;
