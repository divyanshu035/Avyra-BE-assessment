require("dotenv").config();
const express = require("express");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");
const authMiddleware = require("./middleware/auth");

const app = express();
app.use(express.json());

// connect Mongo
connectDB();

// public routes
app.use("/api/auth", authRoutes);

// 🔒 protected routes (must be below middleware)
app.get("/api/protected", authMiddleware, (req, res) => {
  res.json({ message: `Welcome ${req.user.email}, authorized access granted.` });
});

// fallback route
app.get("/", (req, res) => {
  res.send("✅ Backend is running");
});

app.listen(process.env.PORT, () => {
  console.log(`🚀 Server running on port ${process.env.PORT}`);
});
