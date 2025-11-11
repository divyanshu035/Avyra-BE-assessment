const jwt = require("jsonwebtoken");
const User = require("../models/user");

const requireAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized - missing token" });
    }
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password -passwordResetToken -passwordResetExpires");
    if (!user) return res.status(401).json({ message: "Unauthorized - user not found" });
    req.user = user; // attaching for handlers
    next();
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(401).json({ message: "Unauthorized - invalid token" });
  }
};

module.exports = requireAuth;
