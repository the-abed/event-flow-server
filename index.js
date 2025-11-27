import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// MongoDB setup
const client = new MongoClient(process.env.MONGO_URI);
const JWT_SECRET = process.env.JWT_SECRET;

async function run() {
  try {
    await client.connect();
    console.log("MongoDB connected");

    const db = client.db("eventFlow_db"); // database name
    const eventsCollection = db.collection("events"); // collection name
    const users = db.collection("users");

    // Root test route
    app.get("/", (req, res) => {
      res.send("<h1>EventFlow Backend is Running!</h1><p>Use /api/events to GET or POST events.</p>");
    });


    // Configure Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:5000/api/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      const email = profile.emails[0].value;
      let user = await users.findOne({ email });
      if (!user) {
        const result = await users.insertOne({
          name: profile.displayName,
          email,
          googleId: profile.id,
          createdAt: new Date(),
        });
        user = { _id: result.insertedId, name: profile.displayName, email };
      }
      done(null, user);
    }
  )
);

app.use(passport.initialize());

// Google OAuth routes
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/api/auth/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/login" }),
  (req, res) => {
    // Generate JWT after successful login
    const token = jwt.sign({ id: req.user._id, email: req.user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?token=${token}`); // send token to frontend
  }
);

// Register
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ message: "All fields required" });

  const existing = await users.findOne({ email });
  if (existing) return res.status(400).json({ message: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const result = await users.insertOne({ name, email, password: hashed, createdAt: new Date() });

  res.status(201).json({ message: "User registered", userId: result.insertedId });
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "All fields required" });

  const user = await users.findOne({ email });
  if (!user) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid password" });

  const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ message: "Login successful", token });
});

    // Create a new event (POST)
    app.post("/api/events", async (req, res) => {
      try {
        const { title, description, date, location } = req.body;

        if (!title || !date || !location) {
          return res.status(400).json({ message: "Title, date, and location are required." });
        }

        const result = await eventsCollection.insertOne({
          title,
          description: description || "",
          date: new Date(date),
          location,
          createdAt: new Date(),
          updatedAt: new Date(),
        });

        res.status(201).json({ message: "Event created successfully!", event: result });
      } catch (err) {
        res.status(500).json({ message: "Error creating event", error: err.message });
      }
    });

    // Get all events (GET)
    app.get("/api/events", async (req, res) => {
      try {
        const allEvents = await eventsCollection.find().toArray();
        res.json(allEvents);
      } catch (err) {
        res.status(500).json({ message: "Error fetching events", error: err.message });
      }
    });

    // Get single event by ID
    app.get("/api/events/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const event = await eventsCollection.findOne({ _id: new ObjectId(id) });
        if (!event) return res.status(404).json({ message: "Event not found" });
        res.json(event);
      } catch (err) {
        res.status(500).json({ message: "Error fetching event", error: err.message });
      }
    });

  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
}


const initPromise = run();

export default async (req, res) => {
  await initPromise;
  app(req, res);
};


