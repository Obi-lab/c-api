import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const SALT_ROUNDS = 10;

export const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "24h" });
};

export const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
};

export const hashPassword = async (password) => {
  return bcrypt.hash(password, SALT_ROUNDS);
};

export const comparePassword = async (password, hash) => {
  return bcrypt.compare(password, hash);
};

// Enhanced authentication middleware with user data attachment
export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }

    // Set userId in request
    req.userId = decoded.userId;

    // If you want to attach full user data, uncomment this section
    /*
    const db = await readDB();
    const user = db.users.find(u => u.id === decoded.userId);
    if (user) {
      const { password, ...userData } = user;
      req.user = userData;
    }
    */

    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: "Authentication failed" });
  }
};

// Optional middleware to attach full user data when needed
export const attachUserData = async (req, res, next) => {
  try {
    if (!req.userId) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const db = await readDB();
    const user = db.users.find(u => u.id === req.userId);
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Attach user data excluding password
    const { password, ...userData } = user;
    req.user = userData;

    next();
  } catch (error) {
    console.error('Error attaching user data:', error);
    res.status(500).json({ error: "Server error" });
  }
};

