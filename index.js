import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fetch from "node-fetch";
import session from "express-session";
import passport from "passport";
import dotenv from "dotenv";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

dotenv.config(); // loads moneyflow-backend/.env

const app = express();

// PRODUCTION FRONTEND URL
const FRONTEND_URL = "https://moneyflow-frontend.onrender.com";

// Middleware
app.use(
  cors({
    origin: [
      "http://localhost:5173",        // local dev
      FRONTEND_URL                   // deployed frontend
    ],
    credentials: true,
  })
);

app.use(express.json());
app.use(
  session({
    secret: "moneyflow_secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// ==========================
// 🔥 CONNECT TO MONGODB ATLAS
// ==========================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected (Atlas)"))
  .catch((err) => console.error("MongoDB Error:", err));

// ==========================
// 📌 MODELS
// ==========================
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    email: { type: String, unique: true },
    password: String,
    googleId: String,
    username: String,
    base_currency: { type: String, default: "INR" },
  })
);

const Expense = mongoose.model(
  "Expense",
  new mongoose.Schema({
    userId: { type: String, required: true },
    amount: Number,
    category: String,
    note: String,
    currency: { type: String, default: "INR" },
    date: { type: Date, default: Date.now },
  })
);

// ==========================
// 🔥 GOOGLE OAUTH
// ==========================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        user = await User.findOne({ email: profile.emails[0].value });

        if (!user) {
          user = await new User({
            googleId: profile.id,
            email: profile.emails[0].value,
            username: profile.displayName,
          }).save();
        } else {
          user.googleId = profile.id;
          await user.save();
        }
      }

      done(null, user);
    }
  )
);

passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// ==========================
// 🔥 CURRENCY CACHE
// ==========================
let rates = { INR: 1 };

async function updateRates() {
  try {
    const res = await fetch("https://api.frankfurter.app/latest?base=INR");
    const data = await res.json();
    rates = { ...data.rates, INR: 1 };
    console.log("Currency rates updated");
  } catch (e) {
    console.log("Currency API failed", e);
  }
}

updateRates();
setInterval(updateRates, 12 * 60 * 60 * 1000);

// ==========================
// 🔥 AUTH MIDDLEWARE
// ==========================
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ msg: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ msg: "Invalid token" });

    req.user = { id: payload.id };
    next();
  });
};

// ==========================
// ROUTES
// ==========================

// Root
app.get("/", (req, res) => res.send("MoneyFlow Backend Running 🔥"));

// Google OAuth Login
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google OAuth Callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: `${FRONTEND_URL}/login`,
  }),
  (req, res) => {
    const token = jwt.sign({ id: req.user._id }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.redirect(
      `${FRONTEND_URL}/google-callback?token=${token}&email=${req.user.email}&username=${req.user.username}`
    );
  }
);

// ==========================
// 📌 REGISTER + LOGIN
// ==========================
app.post("/api/register", async (req, res) => {
  const { email, password, username } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      password: hashed,
      username,
    });

    res.json({ msg: "Registered!" });
  } catch (e) {
    res.status(400).json({ msg: "Email already exists" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user)
    return res.status(401).json({ msg: "Invalid email or password" });

  if (!user.password)
    return res.status(401).json({ msg: "Use Google Login for this account" });

  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.status(401).json({ msg: "Invalid email or password" });

  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

  res.json({
    token,
    user: {
      id: user._id,
      email: user.email,
      username: user.username,
      base_currency: user.base_currency,
    },
  });
});

// ==========================
// 📌 EXPENSE CRUD
// ==========================
app.get("/api/expenses", authenticate, async (req, res) => {
  const data = await Expense.find({ userId: req.user.id }).sort({
    date: -1,
  });
  res.json(data);
});

app.post("/api/expenses", authenticate, async (req, res) => {
  const expense = await Expense.create({
    ...req.body,
    userId: req.user.id,
  });

  res.json(expense);
});

app.delete("/api/expenses/:id", authenticate, async (req, res) => {
  await Expense.deleteOne({ _id: req.params.id, userId: req.user.id });
  res.json({ msg: "Deleted" });
});

// ==========================
// 📌 SEARCH ROUTE
// ==========================
app.get("/api/search", authenticate, async (req, res) => {
  const q = req.query.q || "";

  const results = await Expense.find({
    userId: req.user.id,
    $or: [
      { category: { $regex: q, $options: "i" } },
      { note: { $regex: q, $options: "i" } },
    ],
  });

  res.json(results);
});

// ==========================
// 🔥 HISTORY
// ==========================
app.get("/api/history", authenticate, async (req, res) => {
  const expenses = await Expense.find({ userId: req.user.id }).sort({
    date: -1,
  });
  res.json(expenses);
});

// ==========================
// 📌 CURRENCY RATES
// ==========================
app.get("/api/currency", (req, res) => {
  res.json({ rates });
});

// ==========================
// SERVER START
// ==========================
app.listen(PORT, () =>
  console.log(`Backend running on port ${PORT} 🚀`)
);
