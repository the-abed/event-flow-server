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

// Fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve uploads folder
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// MongoDB setup
const client = new MongoClient(process.env.MONGO_URI);
const JWT_SECRET = process.env.JWT_SECRET;

let users, eventsCollection;

// Run database connection
async function run() {
  try {
    await client.connect();
    console.log("MongoDB connected");

    const db = client.db("eventFlow_db");

    users = db.collection("users");
    eventsCollection = db.collection("events");

  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
}
run();

// -------------------------
// 🔐 AUTH (REGISTER + LOGIN)
// -------------------------

// Register
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ message: "All fields required" });

  const existing = await users.findOne({ email });
  if (existing)
    return res.status(400).json({ message: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);

  const result = await users.insertOne({
    name,
    email,
    password: hashed,
    createdAt: new Date(),
  });

  res.status(201).json({ message: "User registered", userId: result.insertedId });
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await users.findOne({ email });
  if (!user) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid password" });

  const token = jwt.sign(
    { id: user._id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ message: "Login successful", token });
});

// --------------------
// 🔒 Middleware for JWT
// --------------------
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
}

// ------------------------------
// 📸 Multer config for image upload
// ------------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) =>
    cb(null, path.join(__dirname, "uploads")),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// -----------------------
// ➕ CREATE EVENT (POST)
// -----------------------
app.post("/api/events", verifyToken, async (req, res) => {
  const { title, description, date, location, image } = req.body;

  if (!title || !date || !location || !image) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const newEvent = {
    title,
    description,
    date: new Date(date),
    location,
    image,
    createdBy: new ObjectId(req.user.id),
    createdAt: new Date(),
  };

  const result = await eventsCollection.insertOne(newEvent);

  res.status(201).json({
    message: "Event created successfully",
    event: { ...newEvent, _id: result.insertedId },
  });
});

// -----------------------
// 🟢 GET ALL EVENTS
// -----------------------
app.get("/api/events", async (req, res) => {
  const events = await eventsCollection.find().toArray();
  res.json(events);
});

// -----------------------
// 👤 GET MY EVENTS
// -----------------------
app.get("/api/events/my-events", verifyToken, async (req, res) => {
  const myEvents = await eventsCollection
    .find({ createdBy: new ObjectId(req.user.id) })
    .toArray();

  res.json(myEvents);
});

// -----------------------
// 🔍 GET SINGLE EVENT
// -----------------------
app.get("/api/events/:id", async (req, res) => {
  const event = await eventsCollection.findOne({
    _id: new ObjectId(req.params.id),
  });

  if (!event) return res.status(404).json({ message: "Event not found" });

  res.json(event);
});

app.listen(PORT, () => console.log(`Server running on PORT ${PORT}`));
