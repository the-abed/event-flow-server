import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// Fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve uploads folder
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// MongoDB setup
const client = new MongoClient(process.env.MONGO_URI);
let users, eventsCollection;

// --------------------
// 🛡️ Middleware for JWT
// --------------------
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Adds user {id, email} to the request
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
}

// ------------------------------
// 📸 Multer config
// ------------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, "uploads")),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// -------------------------
// 🚀 Initialization & DB
// -------------------------
async function startServer() {
  try {
    await client.connect();
    const db = client.db("eventFlow_db");
    users = db.collection("users");
    eventsCollection = db.collection("events");
    console.log("✅ Connected to MongoDB");

    // Start listening ONLY after DB connection is successful
    app.listen(PORT, () => console.log(`🚀 Server running on PORT ${PORT}`));
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1); // Stop the process if DB fails
  }
}

// -------------------------
// 🔐 AUTH ROUTES
// -------------------------

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "All fields required" });

    const existing = await users.findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const result = await users.insertOne({
      name,
      email,
      password: hashed,
      createdAt: new Date(),
    });

    res.status(201).json({ message: "User registered", userId: result.insertedId });
  } catch (error) {
    res.status(500).json({ message: "Server error during registration" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await users.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Server error during login" });
  }
});

// -----------------------
// 📅 EVENT ROUTES
// -----------------------

// Get all events (Public)
app.get("/api/events", async (req, res) => {
  const events = await eventsCollection.find().toArray();
  res.json(events);
});

// Get My Events (Protected) - Added verifyToken here!
app.get("/api/events/my-events", verifyToken, async (req, res) => {
  try {
    const userEmail = req.user.email; 
    const events = await eventsCollection
      .find({ creatorEmail: userEmail })
      .sort({ date: 1 })
      .toArray();
    res.json(events);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch user events" });
  }
});

// Create Event (Protected)
app.post("/api/events", verifyToken, async (req, res) => {
  const { title, description, date, location, image } = req.body;

  const newEvent = {
    title,
    description,
    date: new Date(date),
    location,
    image,
    creatorEmail: req.user.email, // Associate event with user
    createdAt: new Date(),
  };

  const result = await eventsCollection.insertOne(newEvent);
  res.status(201).json({ message: "Created", event: { ...newEvent, _id: result.insertedId } });
});

startServer();