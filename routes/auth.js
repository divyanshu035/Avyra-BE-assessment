const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("../models/user");
const authMiddleware = require("../middleware/auth");

const router = express.Router();

function signToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
}

// PUBLIC: Register
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "User already exists" });

    const user = await User.create({ email, password });
    const token = signToken(user);
    res.status(201).json({ message: "User registered", token });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// PUBLIC: Login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid credentials" });

    const valid = await user.comparePassword(password);
    if (!valid)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = signToken(user);
    res.json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// PUBLIC: Forgot password
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user)
      return res
        .status(200)
        .json({ message: "If email exists, reset link sent" });

    const resetToken = user.createResetToken();
    await user.save({ validateBeforeSave: false });

    // NOTE: In real-world, send resetToken via email. Here we return it.
    res.json({
      message: "Password reset token generated",
      resetToken,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// 🔒 PROTECTED: Reset password (user must be authenticated)
router.post("/reset-password", authMiddleware, async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const hashed = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      _id: req.user.id, // ensure the requester is the owner
      passwordResetToken: hashed,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user)
      return res.status(400).json({ message: "Token invalid or expired" });

    user.password = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

module.exports = router;
