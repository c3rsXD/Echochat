// ===== server.js =====
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
const util = require("util");

// --- Realtime & crypto & upload ---
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const multer = require("multer");

const app = express();

// ===== Middleware =====
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ===== Session Configuration =====
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

// ===== Database Connection =====
mongoose
  .connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/echochat", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// ===== Models (User + Message) =====
// If you already have models files, you can require them instead.
// For clarity we define them here (keeps single-file replacement).
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  // For text messages:
  ciphertext: { type: String },
  iv: { type: String },
  // For file messages:
  isFile: { type: Boolean, default: false },
  originalName: { type: String },
  storedFileName: { type: String }, // encrypted file path under uploads
  mimeType: { type: String },
  timestamp: { type: Date, default: Date.now },
});
const Message = mongoose.model("Message", messageSchema);

// ===== Auth Middleware =====
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect("/login.html");
}

// ===== AES helpers =====
// Use AES key from .env if available (hex). Otherwise generate once.
const AES_KEY =
  (process.env.AES_SECRET_KEY && Buffer.from(process.env.AES_SECRET_KEY, "utf8").slice(0,32)) ||
  crypto.randomBytes(32);

// encrypt plain string -> {ciphertext, iv}
function encryptMessage(plainText) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, iv);
  let encrypted = cipher.update(plainText, "utf8", "hex");
  encrypted += cipher.final("hex");
  return { ciphertext: encrypted, iv: iv.toString("hex") };
}

// decrypt ciphertext hex -> plaintext (throws on bad decrypt)
function decryptMessage(ciphertextHex, ivHex) {
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, iv);
  let decrypted = decipher.update(ciphertextHex, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ===== Upload storage (multer) =====
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "uploads"));
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  }
});
const upload = multer({ storage });

// ===== Routes (existing auth routes kept) =====
app.get("/", (req, res) => {
  if (req.session.userId) return res.redirect("/chat.html");
  res.redirect("/login.html");
});

app.post("/register", async (req, res) => {
  try {
    const existing = await User.findOne({ username: req.body.username });
    if (existing) return res.status(400).json({ message: "Username already exists" });

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ username: req.body.username, password: hashedPassword });
    await user.save();
    console.log("✅ Registered:", user.username);

    req.session.userId = user._id;
    res.redirect("/login.html");
  } catch (err) {
    console.error("❌ Registration Error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) return res.status(400).json({ message: "User not found" });

    const valid = await bcrypt.compare(req.body.password, user.password);
    if (!valid) return res.status(400).json({ message: "Invalid password" });

    req.session.userId = user._id;
    console.log("✅ Logged in:", user.username);
    res.redirect("/chat.html");
  } catch (err) {
    console.error("❌ Login Error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/chat.html", isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "chat.html"));
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error("❌ Logout Error:", err);
    res.redirect("/login.html");
  });
});

app.get("/api/me", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select("username");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ username: user.username });
  } catch (err) {
    console.error("❌ /api/me error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/users", isAuthenticated, async (req, res) => {
  try {
    const me = await User.findById(req.session.userId).select("username");
    const users = await User.find({ username: { $ne: me.username } }).select("username");
    res.json(users);
  } catch (err) {
    console.error("❌ /api/users error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// fetch text conversation (decrypted)
app.get("/api/messages/:other", isAuthenticated, async (req, res) => {
  try {
    const me = await User.findById(req.session.userId).select("username");
    const other = req.params.other;

    const msgs = await Message.find({
      $or: [
        { sender: me.username, receiver: other },
        { sender: other, receiver: me.username },
      ],
    }).sort({ timestamp: 1 });

    const result = msgs.map((m) => {
      if (m.isFile) {
        return {
          sender: m.sender,
          receiver: m.receiver,
          isFile: true,
          originalName: m.originalName,
          mimeType: m.mimeType,
          storedFileName: m.storedFileName,
          timestamp: m.timestamp,
        };
      } else {
        return {
          sender: m.sender,
          receiver: m.receiver,
          text: decryptMessage(m.ciphertext, m.iv),
          timestamp: m.timestamp,
        };
      }
    });

    res.json(result);
  } catch (err) {
    console.error("❌ /api/messages error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ===== Upload endpoint (multipart/form-data) =====
// Called by frontend to upload a file to 'to' user.
app.post("/upload", isAuthenticated, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file" });
    const me = await User.findById(req.session.userId).select("username");
    const to = req.body.to;
    if (!to) return res.status(400).json({ message: "No recipient" });

    // read uploaded temp file
    const filePath = req.file.path;
    const buffer = await util.promisify(fs.readFile)(filePath);

    // encrypt file buffer using AES_KEY and iv
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);

    // write encrypted file with .enc
    const storedFileName = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}.enc`;
    const storedPath = path.join(uploadsDir, storedFileName);
    await util.promisify(fs.writeFile)(storedPath, encrypted);

    // delete original temp upload
    await util.promisify(fs.unlink)(filePath);

    // create DB message row to represent the file (store iv in hex)
    const msg = new Message({
      sender: me.username,
      receiver: to,
      isFile: true,
      originalName: req.file.originalname,
      storedFileName,
      mimeType: req.file.mimetype,
      iv: iv.toString("hex"),
    });
    await msg.save();

    // emit socket event to recipient and sender
    const payload = {
      sender: me.username,
      receiver: to,
      isFile: true,
      originalName: msg.originalName,
      mimeType: msg.mimeType,
      storedFileName: msg.storedFileName,
      timestamp: msg.timestamp,
    };

    io.emit("fileMessage", payload); // broadcast (clients will filter)
    return res.json({ success: true, payload });
  } catch (err) {
    console.error("❌ /upload error:", err);
    return res.status(500).json({ message: "Upload error" });
  }
});

// ===== Serve decrypted file on demand =====
// endpoint: GET /files/:storedFileName
// decrypts stored .enc and streams as original mime type
app.get("/files/:storedFileName", isAuthenticated, async (req, res) => {
  try {
    const storedFileName = req.params.storedFileName;
    const msg = await Message.findOne({ storedFileName });
    if (!msg) return res.status(404).send("File not found");

    const encPath = path.join(uploadsDir, storedFileName);
    if (!fs.existsSync(encPath)) return res.status(404).send("File missing on server");

    const encryptedBuffer = await util.promisify(fs.readFile)(encPath);
    const iv = Buffer.from(msg.iv, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

    res.setHeader("Content-Type", msg.mimeType || "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(msg.originalName)}"`);
    res.send(decrypted);
  } catch (err) {
    console.error("❌ /files error:", err);
    // bad decrypts will surface here if AES_KEY changed between sessions
    res.status(500).send("Failed to serve file");
  }
});

// ===== Realtime (Socket.IO) =====
const server = http.createServer(app);
const io = new Server(server);
const online = new Map();

io.on("connection", (socket) => {
  console.log("🔌 Socket connected:", socket.id);

  socket.on("join", (username) => {
    if (!username) return;
    online.set(username, socket.id);
    socket.username = username;
    console.log(`🟢 ${username} joined (socket ${socket.id})`);
    io.emit("user_online", { username });
  });

  // text messages over socket (existing behavior)
  socket.on("sendMessage", async (data) => {
    try {
      const from = socket.username;
      const to = data.to;
      const text = data.text;
      if (!from || !to || !text) return;

      const { ciphertext, iv } = encryptMessage(text);
      const msg = new Message({ sender: from, receiver: to, ciphertext, iv });
      await msg.save();

      // debug log
      console.log("💾 Saved text message:", { from, to, ciphertext, iv });

      const payload = { sender: from, receiver: to, text, timestamp: msg.timestamp };
      // send to specific receiver if online
      const receiverSocketId = online.get(to);
      if (receiverSocketId) io.to(receiverSocketId).emit("newMessage", payload);
      socket.emit("newMessage", payload);
    } catch (err) {
      console.error("❌ sendMessage error:", err);
    }
  });

  socket.on("disconnect", () => {
    if (socket.username) {
      online.delete(socket.username);
      console.log(`🔴 ${socket.username} disconnected (socket ${socket.id})`);
      io.emit("user_offline", { username: socket.username });
    } else {
      console.log("⚪ socket disconnected:", socket.id);
    }
  });
});

// ===== Server Start =====
const PORT = process.env.PORT || 3000;
server.listen(PORT, () =>
  console.log(`🚀 Server (HTTP+Socket.IO) running on http://localhost:${PORT}`)
);
