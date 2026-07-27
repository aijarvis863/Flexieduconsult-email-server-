require("dotenv").config(); // Fixed typo: lowercase 'require'
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

const app = express();

// -------------------------------------------------------------------
// Enhanced CORS & Parsing Middleware
// -------------------------------------------------------------------
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

// -------------------------------------------------------------------
// 1. Initialize Firebase Admin SDK
// -------------------------------------------------------------------
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// -------------------------------------------------------------------
// 2. Configure Email Transporter (Nodemailer)
// -------------------------------------------------------------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// -------------------------------------------------------------------
// Health Check / Root Endpoint
// -------------------------------------------------------------------
app.get("/", (req, res) => {
  res.send("Flexi OTP Service is running live!");
});

// -------------------------------------------------------------------
// 3. Endpoint: Send OTP
// -------------------------------------------------------------------
app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required." });
  }

  try {
    // Check if user exists in Firebase Auth
    const user = await admin.auth().getUserByEmail(email);

    // Generate random 6-digit OTP code
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes expiry

    // Save OTP details in Firestore
    await db.collection("resetOTPs").doc(email).set({
      otp: otp,
      uid: user.uid,
      expiresAt: expiresAt,
    });

    // Send styled email
    await transporter.sendMail({
      from: '"Flexi Educational Consult" <no-reply@flexieduconsult.com.ng>',
      to: email,
      subject: "Your Password Reset OTP Code",
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #002147; border: 1px solid #e0e0e0; border-radius: 8px; max-width: 500px;">
          <h2 style="color: #002147; margin-top: 0;">Flexi Educational Consult</h2>
          <p style="font-size: 15px;">You requested to reset your password. Use the code below to complete the process:</p>
          <div style="text-align: center; margin: 20px 0;">
            <span style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #2b7a43; background: #f0f7f2; padding: 10px 20px; border-radius: 6px; border: 1px dashed #2b7a43; display: inline-block;">
              ${otp}
            </span>
          </div>
          <p style="font-size: 13px; color: #666666;">This code is valid for 10 minutes. If you did not request this, please ignore this email.</p>
        </div>
      `,
    });

    return res.status(200).json({ success: true, message: "OTP code sent to your email!" });
  } catch (error) {
    console.error("Error in /api/send-otp:", error);

    if (error.code === "auth/user-not-found") {
      return res.status(404).json({ success: false, message: "No account found with this email." });
    }

    return res.status(500).json({ success: false, message: "Error sending OTP email. Please try again." });
  }
});

// -------------------------------------------------------------------
// 4. Endpoint: Verify OTP & Reset Password
// -------------------------------------------------------------------
app.post("/api/verify-otp", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.status(400).json({ success: false, message: "Missing required fields." });
  }

  try {
    const docRef = db.collection("resetOTPs").doc(email);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(400).json({ success: false, message: "No OTP request found for this email." });
    }

    const data = doc.data();

    // Verify code match
    if (data.otp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP code." });
    }

    // Verify code expiration
    if (Date.now() > data.expiresAt) {
      return res.status(400).json({ success: false, message: "OTP code has expired. Please request a new one." });
    }

    // Reset user password via Firebase Admin SDK
    await admin.auth().updateUser(data.uid, {
      password: newPassword,
    });

    // Delete used OTP record from Firestore
    await docRef.delete();

    return res.status(200).json({ success: true, message: "Password updated successfully!" });
  } catch (error) {
    console.error("Error in /api/verify-otp:", error);
    return res.status(500).json({ success: false, message: "Failed to reset password. Please try again." });
  }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
