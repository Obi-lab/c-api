// server.js
import express from "express";
import cors from "cors";
import fs from "fs/promises";
import { v4 as uuidv4 } from "uuid";
import * as XLSX from "xlsx";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import xlsx from "xlsx";
import { parse } from "csv-parse/sync";
import { promises as fsPromises } from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// CORS configuration
const corsOptions = {
  origin: process.env.CLIENT_URL || "*",
  hods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["Authorization"],
  credentials: true,
  maxAge: 86400, // 24 hours
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());

import {
  generateToken,
  hashPassword,
  comparePassword,
  authenticateToken,
} from "./auth.js";

const db = {
  users: [
    {
      id: String,
      name: String,
      email: String,
      phone: String || null,
      password: String, // Hashed
      createdAt: String,
    },
  ],
  communities: [
    {
      id: String,
      communityId: String,
      userId: String,
      username: String,
      content: String,
      timestamp: String,
      likes: String,
      replies: [],
    },
  ],
  messages: [
    {
      id: String,
      communityId: String,
      content: String,
      userId: String,
      user_name: String,
      timestamp: String,
    },
  ],
  topics: [
    {
      id: String,
      title: String,
      description: String,
      creatorId: String,
      rating: Number,
      createdAt: String,
      totalQuizzes: Number,
      difficulty: String, // 'beginner', 'intermediate', 'advanced'
    },
  ],
  quizzes: [
    {
      id: String,
      topicId: String,
      title: String,
      description: String,
      instructions: String,
      estimatedTime: Number,
      difficulty: String,
      points: Number,
      maxAttempts: Number,
      timeLimit: Number, // in minutes
      passingScore: Number,
      showResults: Boolean, // whether to show correct answers after completion
      cooldownPeriod: Number, // hours before retaking
      questions: [
        {
          id: String,
          question: String,
          options: [{ id: String, text: String }],
          correctAnswer: String,
          explanation: String,
        },
      ],
    },
  ],
  userProgress: [
    {
      userId: String,
      quizId: String,
      attemptNumber: Number,
      startedAt: String,
      completedAt: String,
      score: Number,
      answers: Object,
      timeSpent: Number, // in minutes
    },
  ],
  creditData: [
    {
      id: String,
      userId: String,
      source: String, // 'transunion', 'experian', 'equifax'
      data: Object,
      uploadedAt: String,
      status: String, // 'processing', 'completed', 'error'
      processingStep: String, // 'upload', 'save', 'extract', 'complete'
      error: String || null,
    },
  ],
  mpesaTransactions: [
    {
      id: String,
      completionTime: String,
      details: String,
      paidIn: Number,
      withdrawn: Number,
      transactionMonth: String,
      monthlyTotal: Number,
      userId: String,
      uploadId: String,
      category: String,
      partyInfo: {
        name: String,
        phoneNumber: String,
      },
      createdAt: String,
    },
  ],
};
// DB Helper Functions
const readDB = async () => {
  const data = await fs.readFile(
    path.join(__dirname, "../db/db.json"),
    "utf-8"
  );
  return JSON.parse(data);
};

const writeDB = async (data) => {
  await fs.writeFile(
    path.join(__dirname, "../db/db.json"),
    JSON.stringify(data, null, 2)
  );
};
// Routes

// User routes
app.post("/api/auth/register", async (req, res) => {
  try {
    console.log(req.body);

    const { name, email, phone, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const db = await readDB();

    // Check if email exists
    if (db.users.some((u) => u.email === email)) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const hashedPassword = await hashPassword(password);

    const newUser = {
      id: String(Date.now()),
      name,
      email,
      phone: phone || null,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
    };

    db.users.push(newUser);
    await writeDB(db);

    const token = generateToken(newUser.id);
    res.status(201).json({
      token,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        phone: newUser.phone,
      },
    });
  } catch (error) {
    console.log(error);

    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const db = await readDB();

    const user = db.users.find((u) => u.email === email);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const validPassword = await comparePassword(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = generateToken(user.id);
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/verify", authenticateToken, async (req, res) => {
  try {
    res.json({ valid: true });
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
});

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const user = db.users.find((u) => u.id === req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const { password, ...userData } = user;
    res.json(userData);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/auth/update", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const userIndex = db.users.findIndex((u) => u.id === req.user.id);
    if (userIndex === -1) {
      return res.status(404).json({ error: "User not found" });
    }

    const updatedUser = {
      ...db.users[userIndex],
      ...req.body,
      updatedAt: new Date().toISOString(),
    };

    db.users[userIndex] = updatedUser;
    await writeDB(db);

    const { password, ...userData } = updatedUser;
    res.json(userData);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Get all communities with filters
app.get("/api/communities", authenticateToken, async (req, res) => {
  try {
    const { filter = "all" } = req.query;
    const db = await readDB();
    let communities = db.communities;

    if (filter === "joined") {
      // In a real app, you'd filter by user's joined communities
      communities = communities.filter((c) =>
        c.members.includes(req.headers["user-id"])
      );
    } else if (filter === "recent") {
      communities.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      communities = communities.slice(0, 10);
    }

    res.json({ communities });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Get specific community
app.get("/api/communities/:id", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const community = db.communities.find((c) => c.id === req.params.id);

    if (!community) {
      return res.status(404).json({ error: "Community not found" });
    }

    res.json(community);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Create new community
app.post("/api/communities", authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;
    const db = await readDB();

    const newCommunity = {
      id: String(Date.now()),
      name,
      description,
      members: [],
      rating: 0,
      memberCount: 0,
      createdAt: new Date().toISOString(),
      rules: [],
      owner: req.headers["user-id"] || "1",
    };

    db.communities.push(newCommunity);
    await writeDB(db);

    res.status(201).json(newCommunity);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Join community
app.post("/api/communities/:id/join", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const communityIndex = db.communities.findIndex(
      (c) => c.id === req.params.id
    );

    if (communityIndex === -1) {
      return res.status(404).json({ error: "Community not found" });
    }

    const userId = req.headers["user-id"] || "1";

    if (!db.communities[communityIndex].members.includes(userId)) {
      db.communities[communityIndex].members.push(userId);
      db.communities[communityIndex].memberCount =
        db.communities[communityIndex].members.length;
      await writeDB(db);
    }

    res.json({
      success: true,
      message: "Successfully joined the community",
      memberCount: db.communities[communityIndex].memberCount,
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Get community messages
app.get(
  "/api/communities/:id/messages",
  authenticateToken,
  async (req, res) => {
    try {
      const db = await readDB();
      const messages = db.messages.filter(
        (m) => m.communityId === req.params.id
      );

      res.json({
        messages: messages.map((m) => ({
          ...m,
          is_own: m.userId === (req.headers["user-id"] || "1"),
        })),
      });
    } catch (error) {
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Post message to community
app.post(
  "/api/communities/:id/messages",
  authenticateToken,
  async (req, res) => {
    try {
      const { content } = req.body;
      const db = await readDB();

      const newMessage = {
        id: String(Date.now()),
        communityId: req.params.id,
        content,
        userId: req.headers["user-id"] || "1",
        user_name: "User", // In a real app, get from user database
        timestamp: new Date().toISOString(),
      };

      db.messages.push(newMessage);
      await writeDB(db);

      res.status(201).json({
        ...newMessage,
        is_own: true,
      });
    } catch (error) {
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Topic routes
app.get("/api/topics", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const topicsWithQuizCount = db.topics.map((topic) => ({
      ...topic,
      totalQuizzes: db.quizzes.filter((q) => q.topicId === topic.id).length,
    }));
    res.json({ topics: topicsWithQuizCount });
  } catch (error) {
    console.log(error);

    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/topics/:id/quizzes", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const topic = db.topics.find((t) => t.id === req.params.id);
    if (!topic) return res.status(404).json({ error: "Topic not found" });

    const quizzes = db.quizzes
      .filter((q) => q.topicId === req.params.id)
      .map(({ id, title, description, difficulty, estimatedTime, points }) => ({
        id,
        title,
        description,
        difficulty,
        estimatedTime,
        points,
      }));

    res.json({ topic, quizzes });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Quiz routes
app.get("/api/quizzes", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const quizzes = db.quizzes.map(({ id, title }) => ({ id, title }));
    res.json({ quizzes });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/quizzes/:id", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const quiz = db.quizzes.find((q) => q.id === req.params.id);
    if (!quiz) {
      return res.status(404).json({ error: "Quiz not found" });
    }

    const sanitizedQuiz = {
      ...quiz,
      questions: quiz.questions.map((q) => ({
        id: q.id,
        question: q.question,
        options: q.options,
      })),
    };
    res.json(sanitizedQuiz);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/quizzes/:id/submit", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const quiz = db.quizzes.find((q) => q.id === req.params.id);
    const { answers } = req.body;

    let score = 0;
    const totalQuestions = quiz.questions.length;

    quiz.questions.forEach((q) => {
      if (answers[q.id] === q.correctAnswer) score++;
    });

    const progress = {
      userId: req.userId,
      quizId: req.params.id,
      score: (score / totalQuestions) * 100,
      completedAt: new Date().toISOString(),
      answers,
    };

    db.userProgress.push(progress);
    await writeDB(db);

    res.json({
      score: progress.score,
      correctAnswers: score,
      totalQuestions,
      completedAt: progress.completedAt,
    });
  } catch (error) {
    console.log(error);

    res.status(500).json({ error: "Server error" });
  }
});

// app.get("/api/quizzes/progress", authenticateToken, async (req, res) => {
//   try {
//     const db = await readDB();
//     const progress = db.userProgress.filter((p) => p.userId === req.user.id);
//     res.json({ progress });
//   } catch (error) {
//     res.status(500).json({ error: "Server error" });
//   }
// });

app.get("/api/quizzes/:id/progress", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const userProgress = db.userProgress.filter(
      (p) => p.userId === req.userId && p.quizId === req.params.id
    );

    const lastAttempt = userProgress[userProgress.length - 1];
    const canAttempt = await checkQuizAttemptEligibility(
      req.params.id,
      userProgress
    );

    res.json({
      attempts: userProgress.length,
      lastAttempt,
      canAttempt,
    });
  } catch (error) {
    console.log(error);

    res.status(500).json({ error: "Server error" });
  }
});

// start quize
app.post("/api/quizzes/:id/start", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const quiz = db.quizzes.find((q) => q.id === req.params.id);

    const attempt = {
      userId: req.userId,
      quizId: req.params.id,
      attemptNumber: await getAttemptNumber(req.userId, req.params.id),
      startedAt: new Date().toISOString(),
    };

    db.userProgress.push(attempt);
    await writeDB(db);

    res.json(attempt);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// helper function
async function checkQuizAttemptEligibility(quizId, userProgress) {
  const db = await readDB();
  const quiz = db.quizzes.find((q) => q.id === quizId);

  if (userProgress.length >= quiz.maxAttempts) {
    return {
      eligible: false,
      reason: "Maximum attempts reached",
    };
  }

  const lastAttempt = userProgress[userProgress.length - 1];
  if (lastAttempt) {
    const cooldownEnd = new Date(lastAttempt.completedAt);
    cooldownEnd.setHours(cooldownEnd.getHours() + quiz.cooldownPeriod);

    if (new Date() < cooldownEnd) {
      return {
        eligible: false,
        reason: "Cooldown period active",
        nextAttemptTime: cooldownEnd,
      };
    }
  }

  return { eligible: true };
}

async function getAttemptNumber(userId, quizId) {
  const db = await readDB();
  const attempts = db.userProgress.filter(
    (p) => p.userId === userId && p.quizId === quizId
  );
  return attempts.length + 1;
}

// file upload
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(__dirname, "../uploads");
    try {
      await fs.access(uploadDir);
    } catch {
      await fs.mkdir(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(
      null,
      `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`
    );
  },
});
/**
 * FILE UPLOAD
 */

// Helper middleware to verify file ownership
export const verifyFileOwnership = async (req, res, next) => {
  try {
    const { fileId } = req.params;
    console.log("Verifying ownership for fileId:", fileId);
    console.log("User ID:", req.userId);

    const db = await readDB();
    console.log("Credit Data in DB:", db.creditData);

    const creditData = db.creditData?.find((cd) => cd.id === fileId);
    console.log("Found credit data:", creditData);

    if (!creditData) {
      return res.status(404).json({
        error: "File not found",
        details: { fileId, userId: req.userId },
      });
    }

    if (creditData.userId !== req.userId) {
      return res.status(403).json({
        error: "Access denied",
        details: {
          fileId,
          requestedBy: req.userId,
          ownedBy: creditData.userId,
        },
      });
    }

    req.creditData = creditData;
    next();
  } catch (error) {
    console.error("Error verifying file ownership:", error);
    res.status(500).json({
      error: "Server error",
      details: error.message,
    });
  }
};
// Utility function to validate required fields
export const validateRequiredFields = (fields) => {
  return (req, res, next) => {
    const missingFields = fields.filter((field) => !req.body[field]);
    if (missingFields.length > 0) {
      return res.status(400).json({
        error: `Missing required fields: ${missingFields.join(", ")}`,
      });
    }
    next();
  };
};

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "application/vnd.ms-excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "text/csv",
    ];

    if (req.body.source === "mpesa" && file.mimetype !== "text/csv") {
      cb(new Error("Mpesa statements must be in CSV format"));
      return;
    }

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Invalid file type. Allowed types: CSV, XLS, XLSX"));
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
}).single("file");

// Wrap multer middleware to handle errors properly
const uploadMiddleware = (req, res, next) => {
  upload(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({
          error: "Validation failed",
          details: ["File size too large. Maximum size is 5MB"],
        });
      }
      return res.status(400).json({
        error: "Validation failed",
        details: [err.message],
      });
    } else if (err) {
      return res.status(400).json({
        error: "Validation failed",
        details: [err.message],
      });
    }
    next();
  });
};

// Validation middleware specifically for credit data upload
const validateCreditDataUpload = (req, res, next) => {
  const errors = [];

  if (!req.body.source) {
    errors.push("Data source is required");
  } else if (
    !["transunion", "experian", "equifax", "mpesa"].includes(
      req.body.source.toLowerCase()
    )
  ) {
    errors.push(
      "Invalid data source. Must be one of: TransUnion, Experian, Equifax, or Mpesa"
    );
  }

  if (!req.file) {
    errors.push("File is required");
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error: "Validation failed",
      details: errors,
    });
  }

  next();
};

// Update the main processFile function to handle Mpesa
async function processFile(fileId) {
  let db;
  try {
    console.log(`Starting to process file: ${fileId}`);
    db = await readDB();
    const creditDataIndex = db.creditData.findIndex((cd) => cd.id === fileId);

    if (creditDataIndex === -1) {
      console.error(`File not found: ${fileId}`);
      return;
    }

    const creditData = db.creditData[creditDataIndex];
    console.log(`Processing ${creditData.source} file:`, creditData.filePath);

    // Single step: Save file info
    try {
      console.log("Saving file information");
      db.creditData[creditDataIndex].processingStep = "complete";
      db.creditData[creditDataIndex].status = "completed";
      db.creditData[creditDataIndex].data = {
        fileName: creditData.fileName,
        uploadedAt: creditData.uploadedAt,
        fileSize: creditData.fileSize,
      };

      await writeDB(db);
      console.log("File processing completed successfully");
    } catch (error) {
      throw new Error(`Save step failed: ${error.message}`);
    }
  } catch (error) {
    console.error("Processing failed:", error);
    try {
      db = await readDB();
      const creditDataIndex = db.creditData.findIndex((cd) => cd.id === fileId);
      if (creditDataIndex !== -1) {
        db.creditData[creditDataIndex].status = "error";
        db.creditData[creditDataIndex].error = error.message;
        await writeDB(db);
      }
    } catch (dbError) {
      console.error("Failed to update error status:", dbError);
    }
  }
}

// Helper function to read and parse CSV file
async function readMpesaCSV(filePath) {
  try {
    const fileContent = await fs.readFile(filePath, "utf-8");
    return parse(fileContent, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
    });
  } catch (error) {
    console.error("Error reading CSV:", error);
    throw new Error("Failed to read transaction file");
  }
}

// Helper function to process raw CSV data
function processTransactions(rawData) {
  return rawData.map((row) => ({
    completionTime: row["Completion Time"],
    details: row["Details"] || "",
    paidIn: parseFloat(row["Paid In"] || "0"),
    withdrawn: parseFloat(row["Withdrawn"] || "0"),
    transactionMonth: row["Transaction Month"] || "",
    category: determineCategory(row["Details"] || ""),
    partyInfo: extractPartyInfo(row["Details"] || ""),
  }));
}

// Helper to determine transaction category
function determineCategory(details) {
  if (!details) return "OTHER";
  const detailsLower = details.toLowerCase();

  if (detailsLower.includes("customer transfer")) return "TRANSFER";
  if (detailsLower.includes("merchant payment")) return "MERCHANT_PAYMENT";
  if (detailsLower.includes("pay bill")) return "PAYBILL";
  if (detailsLower.includes("funds received")) return "RECEIVED";
  if (detailsLower.includes("od loan repayment")) return "LOAN_REPAYMENT";
  if (detailsLower.includes("overdraft of credit")) return "OVERDRAFT";
  if (detailsLower.includes("fuliza")) return "FULIZA";

  return "OTHER";
}

// Helper to extract party information
function extractPartyInfo(details) {
  if (!details) return { name: "", phoneNumber: "" };

  const phoneNumberRegex = /(?:254|\+254|0)?7[0-9]{8}/;
  const maskedPhoneRegex = /(?:254|\+254|0)?7[*]+[0-9]{3}/;

  let phoneNumber = "";
  let name = "";

  const phoneMatch =
    details.match(phoneNumberRegex) || details.match(maskedPhoneRegex);
  if (phoneMatch) {
    phoneNumber = phoneMatch[0];
  }

  if (details.includes("from -")) {
    name = details.split("from -")[1].trim();
  } else if (details.includes("to -")) {
    name = details.split("to -")[1].trim();
  }

  name = name
    .replace(phoneNumberRegex, "")
    .replace(maskedPhoneRegex, "")
    .trim();

  return { name, phoneNumber };
}

async function getUploadFilePath(uploadId, userId) {
  if (!uploadId) {
    throw new Error("No upload ID provided");
  }

  try {
    // Read the database to get file information
    const db = await readDB();
    const uploadInfo = db.creditData?.find(
      (cd) => cd.id === uploadId && cd.userId === userId
    );

    if (!uploadInfo) {
      throw new Error("Upload not found");
    }

    // Return the actual file path from the upload info
    return uploadInfo.filePath;
  } catch (error) {
    console.error("Error getting file path:", error);
    throw new Error("Failed to locate upload file");
  }
}

// Updated transactions endpoint
app.get(
  "/api/mpesa-transactions/:uploadId",
  authenticateToken,
  async (req, res) => {
    try {
      const { uploadId } = req.params;

      if (!uploadId || uploadId === "null") {
        return res.status(400).json({
          error: "Invalid upload ID",
          message: "Please upload a statement first",
        });
      }

      const filePath = await getUploadFilePath(uploadId, req.userId);

      // Check if file exists
      try {
        await fs.access(filePath);
      } catch (error) {
        return res.status(404).json({
          error: "File not found",
          message: "The transaction file could not be found",
        });
      }

      const rawData = await readMpesaCSV(filePath);
      const transactions = processTransactions(rawData);

      res.json({ transactions });
    } catch (error) {
      console.error("Error fetching Mpesa transactions:", error);
      res.status(error.status || 500).json({
        error: "Failed to fetch transactions",
        message: error.message || "An unexpected error occurred",
      });
    }
  }
);

// Updated summary endpoint
app.get(
  "/api/mpesa-transactions/:uploadId/summary",
  authenticateToken,
  async (req, res) => {
    try {
      const { uploadId } = req.params;

      if (!uploadId || uploadId === "null") {
        return res.status(400).json({
          error: "Invalid upload ID",
          message: "Please upload a statement first",
        });
      }

      const filePath = await getUploadFilePath(uploadId, req.userId);

      // Check if file exists
      try {
        await fs.access(filePath);
      } catch (error) {
        return res.status(404).json({
          error: "File not found",
          message: "The transaction file could not be found",
        });
      }

      const rawData = await readMpesaCSV(filePath);
      const transactions = processTransactions(rawData);

      const summary = {
        totalTransactions: transactions.length,
        totalPaidIn: transactions.reduce((sum, t) => sum + (t.paidIn || 0), 0),
        totalWithdrawn: transactions.reduce(
          (sum, t) => sum + (t.withdrawn || 0),
          0
        ),
        transactionsByCategory: transactions.reduce((acc, t) => {
          acc[t.category] = (acc[t.category] || 0) + 1;
          return acc;
        }, {}),
        monthlyTotals: transactions.reduce((acc, t) => {
          if (!acc[t.transactionMonth]) {
            acc[t.transactionMonth] = {
              paidIn: 0,
              withdrawn: 0,
            };
          }
          acc[t.transactionMonth].paidIn += t.paidIn || 0;
          acc[t.transactionMonth].withdrawn += t.withdrawn || 0;
          return acc;
        }, {}),
      };

      res.json({ summary });
    } catch (error) {
      console.error("Error generating Mpesa summary:", error);
      res.status(error.status || 500).json({
        error: "Failed to generate summary",
        message: error.message || "An unexpected error occurred",
      });
    }
  }
);

// Credit Data Upload Routes
app.post(
  "/api/credit-data/upload",
  authenticateToken,
  uploadMiddleware,
  validateCreditDataUpload,
  async (req, res) => {
    try {
      console.log("Starting file upload process");
      const { source } = req.body;
      const { file } = req;

      console.log("File details:", {
        filename: file.originalname,
        size: file.size,
        mimetype: file.mimetype,
      });

      const db = await readDB();
      console.log("Database read successfully");

      if (!db.creditData) {
        db.creditData = [];
      }

      const newCreditData = {
        id: String(Date.now()),
        userId: req.userId,
        source: source.toLowerCase(),
        fileName: file.originalname,
        fileSize: file.size,
        filePath: file.path,
        uploadedAt: new Date().toISOString(),
        status: "processing",
        processingStep: "upload",
        error: null,
        data: null,
      };

      console.log("Created new credit data entry:", newCreditData);

      db.creditData.push(newCreditData);
      await writeDB(db);
      console.log("Updated database with new entry");

      // Start processing in background
      console.log("Starting background processing");
      processFile(newCreditData.id).catch((error) => {
        console.error("Background processing error:", error);
      });

      console.log("Sending response to client");
      res.status(201).json({
        fileId: newCreditData.id,
        fileName: file.originalname,
        status: newCreditData.status,
        step: newCreditData.processingStep,
      });
    } catch (error) {
      console.error("Upload error:", error);

      // Clean up uploaded file if there's an error
      if (req.file) {
        try {
          await fs.unlink(req.file.path);
          console.log("Cleaned up file after error");
        } catch (unlinkError) {
          console.error("Error deleting file:", unlinkError);
        }
      }

      res.status(500).json({
        error: error.message || "Upload failed",
        details: error.stack,
      });
    }
  }
);

app.get(
  "/api/credit-data/status/:fileId",
  authenticateToken,
  verifyFileOwnership,
  async (req, res) => {
    console.log("Status request received for fileId:", req.params.fileId);

    try {
      if (!req.creditData) {
        return res.status(404).json({ error: "Credit data not found" });
      }

      res.json({
        fieldId: req.params.fileId,
        status: req.creditData.status,
        step: req.creditData.processingStep,
        error: req.creditData.error,
        fileInfo: {
          fileName: req.creditData.fileName,
          uploadedAt: req.creditData.uploadedAt,
          fileSize: req.creditData.fileSize,
        },
      });
    } catch (error) {
      console.error("Error in status check:", error);
      res.status(500).json({ error: "Failed to get status" });
    }
  }
);

app.get("/api/credit-data/history", authenticateToken, async (req, res) => {
  try {
    const db = await readDB();
    const userCreditData =
      db.creditData?.filter(
        (cd) => cd.userId === req.userId && cd.status === "completed"
      ) || [];

    res.json({
      creditData: userCreditData.map(({ data, filePath, ...rest }) => rest),
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch credit data history" });
  }
});

// Delete credit data
app.delete(
  "/api/credit-data/:fileId",
  authenticateToken,
  verifyFileOwnership,
  async (req, res) => {
    try {
      const db = await readDB();
      const index = db.creditData.findIndex(
        (cd) => cd.id === req.params.fileId
      );

      db.creditData.splice(index, 1);
      await writeDB(db);

      res.json({ message: "Credit data deleted successfully" });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete credit data" });
    }
  }
);

// Error handling middleware for multer
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res
        .status(400)
        .json({ error: "File size too large. Maximum size is 5MB." });
    }
    return res.status(400).json({ error: error.message });
  }
  next(error);
});

const server = app
  .listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  })
  .on("error", (error) => {
    console.error("Failed to start server:", error);
  });

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

// Keep the process alive even if there's an error
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
});

process.on("unhandledRejection", (error) => {
  console.error("Unhandled Rejection:", error);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM signal received: closing HTTP server");
  server.close(() => {
    console.log("HTTP server closed");
  });
});

export default app;
