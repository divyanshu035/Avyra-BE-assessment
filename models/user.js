const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: { type: String, required: true },
  // For password reset - storing hashed token + expiry
  passwordResetToken: String,
  passwordResetExpires: Date,
  // optional roles field for authorization
  role: { type: String, default: "user" }
}, { timestamps: true });

// Hash password before saving if changed
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password
userSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Creating a reset token and setting up expiry (returns plain token to send to user)
userSchema.methods.createPasswordResetToken = function (expiresInMinutes = 15) {
  const resetToken = crypto.randomBytes(32).toString("hex");
  // store hashed version
  this.passwordResetToken = crypto.createHash("sha256").update(resetToken).digest("hex");
  this.passwordResetExpires = Date.now() + expiresInMinutes * 60 * 1000;
  return resetToken;
};

const User = mongoose.model("User", userSchema);
module.exports = User;
