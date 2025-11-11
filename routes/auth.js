const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const User = require("../models/user");

// helper to sign JWT token
function signToken(user) {
  return jwt.sign({ id: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1h"
  });
}

router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });

    const user = new User({ email, password });
    await user.save();

    const token = signToken(user);
    res.status(201).json({ user: { id: user._id, email: user.email }, token });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// LOGIN
// POST /api/auth/login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = signToken(user);
    res.json({ user: { id: user._id, email: user.email }, token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// FORGOT PASSWORD
// POST /api/auth/forgot-password
// body: { email }
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const user = await User.findOne({ email });
    if (!user) {
      // For security, respond success even if user not found (don't reveal which emails exist)
      return res.json({ message: "If an account with that email exists, a reset token has been generated." });
    }

    const resetToken = user.createPasswordResetToken(parseInt(process.env.RESET_TOKEN_EXPIRES_MIN || "15"));
    await user.save({ validateBeforeSave: false });

    // The token returned is the plain token. The DB stores hashed token.
    res.json({
      message: "Password reset token generated (in production you would email this token).",
      resetToken // client would use this token in reset endpoint
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// RESET PASSWORD
// POST /api/auth/reset-password
// body: { token, newPassword }
router.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ message: "Token and newPassword required" });

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    user.password = newPassword; // pre-save hook will hash
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Optionally sign in the user immediately
    const jwtToken = signToken(user);
    res.json({ message: "Password reset successful", token: jwtToken });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
