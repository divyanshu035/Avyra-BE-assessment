require("dotenv").config();
const express = require("express");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");
const requireAuth = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());

// connect to Mongo
connectDB(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/backend-eval");

// routes
app.use("/api/auth", authRoutes);

// example protected route
app.get("/api/protected", requireAuth, (req, res) => {
  res.json({ message: `Hello ${req.user.email}, this is protected data.`, user: req.user });
});

// health
app.get("/", (req, res) => res.send("Backend running"));

// error handler (basic)
app.use((err, req, res, next) => {
  console.error("Unhandled error: ", err);
  res.status(500).json({ message: "Server error" });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
