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

// const Razorpay = require('razorpay'); // Payment Disabled for now
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
    // The 'to' field can be a string of comma-separated emails or an array.
    const toAddresses = Array.isArray(to)
        ? to
        : to.split(',').map(e => e.trim());

    const params = {
        FromEmailAddress: '"LAKSHYA 2K26" <support@testify-lac.com>', // Using the provided verified email
        Destination: {
            ToAddresses: toAddresses,
        },
        Content: {
            Simple: {
                Subject: {
                    Data: subject,
                    Charset: 'UTF-8',
                },
                Body: {
                    Html: {
                        Data: htmlContent,
                        Charset: 'UTF-8',
                    },
                },
            },
        },
    };

    try {
        const command = new SendEmailCommand(params);
        const data = await sesClient.send(command);
        console.log('Email sent successfully with SES:', data.MessageId);
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
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/static/home.html')));
app.get('/home.html', (req, res) => res.sendFile(path.join(__dirname, 'public/static/home.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/static/login.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public/static/login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'public/static/register.html')));
app.get('/events.html', (req, res) => res.sendFile(path.join(__dirname, 'public/static/events.html')));
app.get('/culturals.html', (req, res) => res.sendFile(path.join(__dirname, 'public/static/culturals.html')));
app.get('/brochure.html', (req, res) => res.sendFile(path.join(__dirname, 'public/static/brochure.html')));
app.get('/committee.html', (req, res) => res.sendFile(path.join(__dirname, 'public/static/committee.html')));
app.get('/contact.html', (req, res) => res.sendFile(path.join(__dirname, 'public/static/contact.html')));


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

        // FIX: Saving DEPT and FULLNAME correctly to session
        req.session.user = { 
            email: user.email, 
            role: user.role, 
            name: user.fullName,
            dept: user.dept // Crucial for Coordinators
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
    
    try {
        await sendEmail(email, "LAKSHYA 2K26 OTP", `Your OTP is: ${otp}`);
        res.json({ message: 'OTP sent', debug_otp: otp });
    } catch (e) {
        res.status(500).json({ error: 'Failed to send OTP', details: e });
    }
});


// --- 9. API ROUTES: MOCKED PAYMENT & REGISTRATION ---
app.post('/api/register-event', isAuthenticated('participant'), async (req, res) => {
    // UPDATED: Now accepts teamName and teamMembers
    const { eventId, deptName, paymentMode, teamName, teamMembers } = req.body;
    const registrationId = uuidv4();
    const user = req.session.user;

    const params = {
        TableName: 'Lakshya_Registrations',
        Item: {
            registrationId,
            studentEmail: user.email,
            eventId,
            deptName,
            // Save Team Details
            teamName: teamName || null, 
            teamMembers: teamMembers || [], // Array of objects
            paymentStatus: paymentMode === 'Online' ? 'PENDING' : 'PENDING_CASH',
            paymentMode,
            attendance: false,
            registeredAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Registration initiated', registrationId });
    } catch (err) {
        console.error("Reg Error", err);
        res.status(500).json({ error: 'Registration failed' });
    }
});
app.post('/api/payment/create-order', async (req, res) => {
    const { amount } = req.body;
    res.json({
        id: "order_mock_" + uuidv4(),
        amount: amount * 100,
        currency: "INR",
        receipt: uuidv4()
    });
});
app.get('/api/participant/dashboard-stats', isAuthenticated('participant'), async (req, res) => {
    const userEmail = req.session.user.email;
    const userName = req.session.user.name;

    const params = {
        TableName: 'Lakshya_Registrations',
        IndexName: 'StudentIndex',
        KeyConditionExpression: 'studentEmail = :email',
        ExpressionAttributeValues: { ':email': userEmail }
    };

    try {
        const data = await docClient.send(new QueryCommand(params));
        const registrations = data.Items || [];
        
        // Calculate payment status
        const total = registrations.length;
        const paid = registrations.filter(r => r.paymentStatus === 'COMPLETED').length;
        
        let status = 'None';
        if (total > 0) {
            if (paid === total) status = 'Paid';
            else if (paid > 0) status = 'Partial';
            else status = 'Pending';
        }

        res.json({
            name: userName,
            totalRegistrations: total,
            paymentStatus: status
        });

    } catch (err) {
        console.error("Dashboard Stats Error:", err);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});


app.post('/api/payment/verify', async (req, res) => {
    const { registrationId, paymentId } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set paymentStatus = :s, paymentId = :p",
        ExpressionAttributeValues: {
            ":s": "COMPLETED",
            ":p": paymentId || "mock_payment_id"
        }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ status: 'success' });
    } catch (err) {
        res.status(500).json({ error: 'Verification failed' });
    }
});

// --- 10. COORDINATOR ROUTES ---
app.post('/api/coordinator/mark-attendance', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId, status } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set attendance = :a",
        ExpressionAttributeValues: { ":a": status }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Attendance updated' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.post('/api/coordinator/mark-paid', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set paymentStatus = :s, paymentMode = :m",
        ExpressionAttributeValues: {
            ":s": "COMPLETED",
            ":m": "CASH"
        }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Payment marked as received' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

// Add this inside your backend.js under Admin Routes

app.get('/api/admin/stats', isAuthenticated('admin'), async (req, res) => {
    try {
        const [users, events, regs] = await Promise.all([
            docClient.send(new ScanCommand({ TableName: 'Lakshya_Users', Select: 'COUNT' })),
            docClient.send(new ScanCommand({ TableName: 'Lakshya_Events', Select: 'COUNT' })),
            docClient.send(new ScanCommand({ TableName: 'Lakshya_Registrations' }))
        ]);

        const registrations = regs.Items || [];
        
        // 1. Calculate Revenue
        const totalRevenue = registrations.reduce((sum, r) => {
            return r.paymentStatus === 'COMPLETED' ? sum + 200 : sum; 
        }, 0);

        // 2. Analytics: Registrations by Department
        const deptCounts = {};
        registrations.forEach(r => {
            const d = r.deptName || 'General';
            deptCounts[d] = (deptCounts[d] || 0) + 1;
        });

        // 3. Analytics: Payment Status
        const paymentCounts = { Paid: 0, Pending: 0 };
        registrations.forEach(r => {
            if(r.paymentStatus === 'COMPLETED') paymentCounts.Paid++;
            else paymentCounts.Pending++;
        });

        res.json({
            totalUsers: users.Count,
            totalEvents: events.Count,
            totalRegistrations: regs.Count,
            totalRevenue: totalRevenue,
            deptCounts: deptCounts,      // For Bar Chart
            paymentCounts: paymentCounts // For Pie Chart
        });

    } catch (err) {
        console.error("Admin Stats Error:", err);
        res.status(500).json({ error: 'Failed to load admin stats' });
    }
});
app.get('/api/admin/student-details', isAuthenticated('admin'), async (req, res) => {
    const { email } = req.query;
    try {
        const data = await docClient.send(new GetCommand({ TableName: 'Lakshya_Users', Key: { email } }));
        if (data.Item) {
            const { password, ...studentData } = data.Item;
            res.json(studentData);
        } else { res.status(404).json({ error: 'Student not found' }); }
    } catch (err) { res.status(500).json({ error: 'Failed to fetch details' }); }
});
app.get('/admin/registrations', isAuthenticated('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/registrations.html'));
});
app.get('/api/admin/all-registrations', isAuthenticated('admin'), async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Registrations' }));
        res.json(data.Items || []);
    } catch (err) {
        console.error("Admin Reg Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch registrations' });
    }
});


app.post('/api/admin/create-user', isAuthenticated('admin'), async (req, res) => {
    const { email, password, role, fullName, dept } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const params = {
        TableName: 'Lakshya_Users',
        Item: {
            email,
            role, // 'coordinator'
            fullName,
            dept, // Store dept for coordinators
            password: hashedPassword,
            createdAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'User created successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Creation failed' });
    }
});
// Add Committee Member
app.post('/api/admin/add-committee-member', isAuthenticated('admin'), async (req, res) => {
    const { name, role, category, imgUrl } = req.body;
    const memberId = uuidv4();

    const params = {
        TableName: 'Lakshya_Committee', // You need to create this table or store in a general config table
        Item: {
            memberId,
            name,
            role,
            category,
            imgUrl
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Member added' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add member' });
    }
});

// Add this inside the "Admin Routes" section of backend.js

// --- 1. Fetch Departments ---
app.get('/api/admin/departments', async (req, res) => {
    const params = { TableName: 'Lakshya_Departments' }; // Create this table in DynamoDB
    try {
        const data = await docClient.send(new ScanCommand(params));
        res.json(data.Items);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch departments' });
    }
});

app.post('/api/admin/add-event', isAuthenticated('admin'), upload.single('image'), async (req, res) => {
    try {
        const { title, type, description, teamSize, fee, departments, sections } = req.body;
        // Note: departments and sections will come as JSON strings if sent via FormData, need parsing.

        let imageUrl = 'default.jpg';

        if (req.file) {
            const fileContent = req.file.buffer;
            const fileName = `events/${uuidv4()}-${req.file.originalname}`;
            const uploadParams = {
                Bucket: 'hirewithusjobapplications',
                Key: fileName,
                Body: fileContent,
                ContentType: req.file.mimetype,
                // ACL: 'public-read' // S3 buckets often block ACLs now, assume bucket policy allows public read or use CloudFront.
                // For this specific bucket name, I'll assume standard config.
            };
            await s3Client.send(new PutObjectCommand(uploadParams));
            imageUrl = `https://hirewithusjobapplications.s3.ap-south-1.amazonaws.com/${fileName}`;
        }

        const eventId = uuidv4();
        const params = {
            TableName: 'Lakshya_Events',
            Item: {
                eventId,
                title,
                type,
                description,
                teamSize,
                fee,
                departments: JSON.parse(departments), // Parse back to array
                sections: JSON.parse(sections),       // Parse back to array
                imageUrl,
                createdAt: new Date().toISOString()
            }
        };
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Event created' });
    } catch (err) {
        console.error("Event Add Error:", err);
        res.status(500).json({ error: 'Failed to create event' });
    }
});

// --- 2. Add Department ---
app.post('/api/admin/add-department', isAuthenticated('admin'), async (req, res) => {
    const { name } = req.body;
    const deptId = uuidv4();
    
    const params = {
        TableName: 'Lakshya_Departments',
        Item: {
            deptId,
            name: name.toUpperCase(),
            createdAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Department added' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add department' });
    }
});
app.post('/api/admin/delete-department', isAuthenticated('admin'), async (req, res) => {
    const { deptId } = req.body;
    
    const params = {
        TableName: 'Lakshya_Departments',
        Key: { deptId }
    };

    try {
        await docClient.send(new DeleteCommand(params));
        res.json({ message: 'Department deleted' });
    } catch (err) {
        console.error("Dept Delete Error:", err);
        res.status(500).json({ error: 'Failed to delete department' });
    }
});
app.get('/api/events', async (req, res) => {
    const params = { TableName: 'Lakshya_Events' };
    try {
        const data = await docClient.send(new ScanCommand(params));
        res.json(data.Items || []);
    } catch (err) {
        console.error("Event Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

// Get My Registrations
app.get('/api/participant/my-registrations-data', isAuthenticated('participant'), async (req, res) => {
    const userEmail = req.session.user.email;
    
    const params = {
        TableName: 'Lakshya_Registrations',
        IndexName: 'StudentIndex',
        KeyConditionExpression: 'studentEmail = :email',
        ExpressionAttributeValues: { ':email': userEmail }
    };

    try {
        const data = await docClient.send(new QueryCommand(params));
        res.json(data.Items);
    } catch (err) {
        console.error("Reg Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch registrations' });
    }
    });
// --- COORDINATOR API ROUTES ---

// 1. Get Dashboard Data (Filtered by Coordinator's Dept)
app.get('/api/coordinator/dashboard-data', isAuthenticated('coordinator'), async (req, res) => {
    try {
        const userDept = req.session.user.dept;
        
        if (!userDept) {
            return res.json({ dept: 'Unknown', registrations: [] });
        }
        
        // 1. Fetch all registrations for department
        const params = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'DepartmentIndex',
            KeyConditionExpression: 'deptName = :dept',
            ExpressionAttributeValues: { ':dept': userDept }
        };

        const data = await docClient.send(new QueryCommand(params));
        let registrations = data.Items || [];

  

        res.json({ dept: userDept, registrations: registrations });
    } catch (err) {
        console.error("Coord Dashboard Error:", err);
        res.status(500).json({ error: 'Failed to load data' });
    }
});

// 2. Quick Attendance (By Reg ID or Email - Simplified lookup)
app.post('/api/coordinator/quick-attendance', isAuthenticated('coordinator'), async (req, res) => {
    const { identifier } = req.body; // Can be Reg ID
    
    // Ideally, we scan or query. For simplicity, let's assume it's the Registration ID (Partition Key)
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
            res.json({ 
                message: 'Success', 
                studentEmail: data.Attributes.studentEmail,
                eventId: data.Attributes.eventId
            });
        } else {
            res.status(404).json({ error: 'Registration ID not found' });
        }
    } catch (err) {
        console.error("Quick Attend Error:", err);
        res.status(500).json({ error: 'Lookup failed' });
    }
});

app.get('/api/coordinator/dashboard-data', isAuthenticated('coordinator'), async (req, res) => {
    try {
        const userDept = req.session.user.dept;
        
        if (!userDept) {
            return res.json({ dept: 'Unknown', registrations: [] });
        }
        
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
    } catch (err) {
        res.status(500).json({ error: 'Lookup failed' });
    }
});

app.post('/api/coordinator/mark-attendance', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId, status } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set attendance = :a",
        ExpressionAttributeValues: { ":a": status }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Attendance updated' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.post('/api/coordinator/mark-paid', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set paymentStatus = :s, paymentMode = :m",
        ExpressionAttributeValues: { ":s": "COMPLETED", ":m": "CASH" }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Payment marked as received' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.get('/api/coordinator/my-events', isAuthenticated('coordinator'), async (req, res) => {
    const userDept = req.session.user.dept;
    if (!userDept) return res.json([]);

    // In a real app with proper GSIs, we would Query. 
    // Here we scan events and filter in memory (simple for small scale)
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        const allEvents = data.Items || [];
        
        // Filter events where this department is eligible
        const myEvents = allEvents.filter(e => e.departments && e.departments.includes(userDept));
        res.json(myEvents);
    } catch(e) {
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

// ADDED: Fetch students for a specific event
app.get('/api/coordinator/event-students', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId } = req.query;
    const userDept = req.session.user.dept;

    const params = {
        TableName: 'Lakshya_Registrations',
        IndexName: 'DepartmentIndex',
        KeyConditionExpression: 'deptName = :dept',
        FilterExpression: 'eventId = :eid AND paymentStatus = :paid', // Only PAID students
        ExpressionAttributeValues: {
            ':dept': userDept,
            ':eid': eventId,
            ':paid': 'COMPLETED'
        }
    };

    try {
        const data = await docClient.send(new QueryCommand(params));
        res.json(data.Items || []);
    } catch(e) {
        console.error(e);
        res.status(500).json({ error: 'Failed to fetch students' });
    }
});
app.post('/api/coordinator/mark-paid', isAuthenticated('coordinator'), async (req, res) => {
    const { registrationId } = req.body;
    const params = {
        TableName: 'Lakshya_Registrations',
        Key: { registrationId },
        UpdateExpression: "set paymentStatus = :s, paymentMode = :m",
        ExpressionAttributeValues: { 
            ":s": "COMPLETED", 
            ":m": "CASH" 
        }
    };
    try {
        await docClient.send(new UpdateCommand(params));
        res.json({ message: 'Payment marked as received' });
    } catch (err) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.get('/api/coordinator/pending-payments', isAuthenticated('coordinator'), async (req, res) => {
    try {
        const userDept = req.session.user.dept;
        
        const params = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'DepartmentIndex',
            KeyConditionExpression: 'deptName = :dept',
            // Filter: Get everything that is NOT 'COMPLETED'
            FilterExpression: 'paymentStatus <> :paid',
            ExpressionAttributeValues: {
                ':dept': userDept,
                ':paid': 'COMPLETED'
            }
        };

        const data = await docClient.send(new QueryCommand(params));
        res.json(data.Items || []);
    } catch (err) {
        console.error("Pending Payments Error:", err);
        res.status(500).json({ error: 'Failed to fetch data' });
    }
});

app.get('/api/coordinator/student-details', isAuthenticated('coordinator'), async (req, res) => {
    const { email } = req.query;
    try {
        const params = {
            TableName: 'Lakshya_Users',
            Key: { email }
        };
        const data = await docClient.send(new GetCommand(params));
        if (data.Item) {
            // Don't send password
            const { password, ...studentData } = data.Item;
            res.json(studentData);
        } else {
            res.status(404).json({ error: 'Student not found' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch student details' });
    }
});
app.post('/api/coordinator/export-data', isAuthenticated('coordinator'), async (req, res) => {
    const { emails } = req.body; // Array of emails from registrations
    if (!emails || emails.length === 0) return res.json([]);

    // Deduplicate emails
    const uniqueEmails = [...new Set(emails)];
    
    // DynamoDB BatchGetItem has a limit of 100 items (and 16MB). 
    // For simplicity in this project, we will loop GetItem in parallel (Promise.all) 
    // or scan the Users table if the list is huge. 
    // Let's try parallel GetItem for up to 50 items, otherwise Scan + Filter in memory.
    
    try {
        // Efficient approach: Scan Users table and filter in memory (Better for < 1000 users)
        const scanParams = {
            TableName: 'Lakshya_Users',
            // Only fetch needed fields
            ProjectionExpression: 'email, fullName, mobile, college, rollNo' 
        };
        const userData = await docClient.send(new ScanCommand(scanParams));
        const allUsers = userData.Items;

        // Map email -> user details
        const userMap = {};
        allUsers.forEach(u => userMap[u.email] = u);

        res.json(userMap);
    } catch (err) {
        console.error("Export Error:", err);
        res.status(500).json({ error: 'Failed to fetch user details for export' });
    }
});

app.post('/api/admin/save-scheme', isAuthenticated('admin'), async (req, res) => {
    const { eventId, deptName, criteria } = req.body;
    // criteria = [{ name: "Logic", max: 10 }, { name: "Syntax", max: 10 }]
    
    const schemeId = `${eventId}#${deptName}`; // Composite ID

    const params = {
        TableName: 'Lakshya_ScoringSchemes', // Needs to be created in DynamoDB
        Item: {
            schemeId,
            eventId,
            deptName,
            criteria: JSON.parse(criteria),
            updatedAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Scoring scheme saved successfully' });
    } catch (err) {
        console.error("Save Scheme Error:", err);
        res.status(500).json({ error: 'Failed to save scheme' });
    }
});

// 2. COORDINATOR: Get Data for Grading (Scheme + Present Students)
app.get('/api/coordinator/scoring-details', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId } = req.query;
    const deptName = req.session.user.dept;

    if (!eventId || !deptName) return res.status(400).json({ error: "Missing params" });

    try {
        // A. Fetch Scheme
        const schemeId = `${eventId}#${deptName}`;
        const schemeRes = await docClient.send(new GetCommand({
            TableName: 'Lakshya_ScoringSchemes',
            Key: { schemeId }
        }));

        const scheme = schemeRes.Item;
        if (!scheme) {
            return res.json({ enabled: false, message: "Admin has not configured scoring for this event/dept yet." });
        }

        // B. Fetch Students (Only PRESENT ones)
        const regParams = {
            TableName: 'Lakshya_Registrations',
            IndexName: 'DepartmentIndex',
            KeyConditionExpression: 'deptName = :dept',
            FilterExpression: 'eventId = :eid AND attendance = :att', 
            ExpressionAttributeValues: {
                ':dept': deptName,
                ':eid': eventId,
                ':att': true // Only Present
                // Note: In DynamoDB boolean storage, ensure this matches how you saved it (true vs "true")
            }
        };

        const regData = await docClient.send(new QueryCommand(regParams));
        const students = regData.Items || [];

        // Check if results are already finalized for this batch
        // We can store a 'locked' flag on the Scheme or check individual students.
        // Let's check the scheme first.
        const isLocked = scheme.isLocked === true;

        res.json({
            enabled: true,
            scheme: scheme.criteria,
            isLocked: isLocked,
            students: students.map(s => ({
                registrationId: s.registrationId,
                studentEmail: s.studentEmail,
                totalScore: s.totalScore || 0,
                scoreBreakdown: s.scoreBreakdown || {}, // { "Logic": 8, "Syntax": 5 }
            }))
        });

    } catch (err) {
        console.error("Scoring Details Error:", err);
        res.status(500).json({ error: "Failed to load scoring data" });
    }
});

// 3. COORDINATOR: Submit/Finalize Scores
app.post('/api/coordinator/submit-scores', isAuthenticated('coordinator'), async (req, res) => {
    const { eventId, scores, finalize } = req.body; 
    // scores = [ { registrationId: "...", breakdown: {...}, total: 50 }, ... ]
    const deptName = req.session.user.dept;

    try {
        // 1. Update each student's record
        // DynamoDB BatchWriteItem doesn't support updates, so we use Promise.all with UpdateCommand
        const updatePromises = scores.map(student => {
            return docClient.send(new UpdateCommand({
                TableName: 'Lakshya_Registrations',
                Key: { registrationId: student.registrationId },
                UpdateExpression: "set scoreBreakdown = :sb, totalScore = :ts",
                ExpressionAttributeValues: {
                    ":sb": student.breakdown,
                    ":ts": student.total
                }
            }));
        });

        await Promise.all(updatePromises);

        // 2. If Final Submit, Lock the Scheme
        if (finalize) {
            const schemeId = `${eventId}#${deptName}`;
            await docClient.send(new UpdateCommand({
                TableName: 'Lakshya_ScoringSchemes',
                Key: { schemeId },
                UpdateExpression: "set isLocked = :l",
                ExpressionAttributeValues: { ":l": true }
            }));
        }

        res.json({ message: finalize ? "Scores Finalized & Locked" : "Scores Saved Successfully" });

    } catch (err) {
        console.error("Submit Scores Error:", err);
        res.status(500).json({ error: "Failed to save scores" });
    }
});

// --- EXISTING APIs (Keep these for context) ---

app.get('/api/events', async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/departments', async (req, res) => {
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Departments' }));
        res.json(data.Items || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/coordinator/my-events', isAuthenticated('coordinator'), async (req, res) => {
    const userDept = req.session.user.dept;
    if (!userDept) return res.json([]);
    try {
        const data = await docClient.send(new ScanCommand({ TableName: 'Lakshya_Events' }));
        const allEvents = data.Items || [];
        const myEvents = allEvents.filter(e => e.departments && e.departments.includes(userDept));
        res.json(myEvents);
    } catch(e) { res.status(500).json({ error: 'Failed' }); }
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
            dept: user.dept 
        };
        
        res.status(200).json({ message: 'Login successful' });
    } catch (err) { res.status(500).json({ error: 'Login failed' }); }
});
// --- 11. API ROUTES: PERSISTENT CART ---

// Get User Cart
app.get('/api/cart', isAuthenticated('participant'), async (req, res) => {
    const email = req.session.user.email;
    const params = {
        TableName: 'Lakshya_Cart', // You must create this table in DynamoDB (PK: email)
        Key: { email }
    };

    try {
        const data = await docClient.send(new GetCommand(params));
        // Return empty array if no cart exists yet
        res.json(data.Item ? data.Item.items : []); 
    } catch (err) {
        console.error("Get Cart Error:", err);
        res.status(500).json({ error: 'Failed to fetch cart' });
    }
});

// Update User Cart (Overwrites existing list)
app.post('/api/cart', isAuthenticated('participant'), async (req, res) => {
    const email = req.session.user.email;
    const { items } = req.body; // Expecting Array of cart items

    const params = {
        TableName: 'Lakshya_Cart',
        Item: {
            email,
            items,
            updatedAt: new Date().toISOString()
        }
    };

    try {
        await docClient.send(new PutCommand(params));
        res.json({ message: 'Cart saved' });
    } catch (err) {
        console.error("Save Cart Error:", err);
        res.status(500).json({ error: 'Failed to save cart' });
    }
});

// Clear Cart
app.delete('/api/cart', isAuthenticated('participant'), async (req, res) => {
    const email = req.session.user.email;
    try {
        await docClient.send(new DeleteCommand({
            TableName: 'Lakshya_Cart',
            Key: { email }
        }));
        res.json({ message: 'Cart cleared' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to clear cart' });
    }
});

app.post('/api/admin/export-data', isAuthenticated('admin'), async (req, res) => {
    const { emails } = req.body;
    if (!emails || emails.length === 0) return res.json({});
    try {
        const scanParams = {
            TableName: 'Lakshya_Users',
            ProjectionExpression: 'email, fullName, mobile, college, rollNo, year'
        };
        const userData = await docClient.send(new ScanCommand(scanParams));
        const userMap = {};
        userData.Items.forEach(u => userMap[u.email] = u);
        res.json(userMap);
    } catch (err) { res.status(500).json({ error: 'Failed to export' }); }
});

app.get('/api/admin/scores', isAuthenticated('admin'), async (req, res) => {
    const { eventId, deptName } = req.query;

    try {
        // Start with a basic scan
        const scanParams = {
            TableName: 'Lakshya_Registrations',
            // Only fetch records that have a score
            FilterExpression: 'attribute_exists(totalScore)' 
        };

        // Apply Filters if specific ones are selected
        const filters = [];
        const attrValues = {};
        const attrNames = {};

        if (eventId && eventId !== 'all') {
            filters.push('eventId = :eid');
            attrValues[':eid'] = eventId;
        }
        if (deptName && deptName !== 'all') {
            filters.push('#d = :dn');
            attrValues[':dn'] = deptName;
            attrNames['#d'] = 'deptName'; // Handle reserved word safety if needed
        }

        if (filters.length > 0) {
            scanParams.FilterExpression += ' AND ' + filters.join(' AND ');
            scanParams.ExpressionAttributeValues = attrValues;
            if (Object.keys(attrNames).length > 0) scanParams.ExpressionAttributeNames = attrNames;
        }

        const data = await docClient.send(new ScanCommand(scanParams));
        let items = data.Items || [];

        // Sort by Score (Descending) to show Rank
        items.sort((a, b) => parseFloat(b.totalScore) - parseFloat(a.totalScore));

        res.json(items);
    } catch (err) {
        console.error("Admin Score Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch scores' });
    }
});
const PORT = process.env.PORT || 3000;

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🚀 LAKSHYA 2K26 Server running on http://localhost:${PORT}`);
    });
}

module.exports = app;
