require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const AWS = require('aws-sdk');
const Razorpay = require('razorpay');
const path = require('path');

const app = express();

// --- 1. CONFIGURATION ---
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// SERVE STATIC FILES (Updated for your folder structure)
// Since your folders (assets, static, js) are at root, we serve the root directory
app.use(express.static(__dirname)); 

app.use(session({
    secret: process.env.SESSION_SECRET || 'temp_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS in prod
}));

// --- 2. AWS & DB SETUP ---
// (Ensure you add these Environment Variables in Vercel Settings)
AWS.config.update({
    region: process.env.AWS_REGION,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

const docClient = new AWS.DynamoDB.DocumentClient();
const ses = new AWS.SES();

// --- 3. ROUTE: SERVE PAGES ---
// Updated paths to match your GitHub structure (No 'public' folder)

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'static/home.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'static/login.html'));
});

// Dashboard Routes
app.get('/dashboard/student', (req, res) => {
    res.sendFile(path.join(__dirname, 'participant/dashboard.html'));
});

app.get('/dashboard/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin/dashboard.html'));
});

app.get('/dashboard/coordinator', (req, res) => {
    res.sendFile(path.join(__dirname, 'coordinator/dashboard.html'));
});

// --- 4. START SERVER ---
// Vercel requires us to export the app, but local dev needs app.listen
const PORT = process.env.PORT || 3000;

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🚀 LAKSHYA 2K26 Server running on http://localhost:${PORT}`);
    });
}

// REQUIRED FOR VERCEL
module.exports = app;
