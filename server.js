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
  .connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/echochat")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// ===== Models (User + Message) =====
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

// ===== AES helpers (using key from .env) =====
const SECRET_KEY_STRING = process.env.AES_SECRET_KEY;
let AES_KEY;

if (SECRET_KEY_STRING) {
  const keyBuffer = Buffer.from(SECRET_KEY_STRING, "utf8");
  // CRITICAL: Ensure key is 32 bytes (256 bits) for AES-256
  AES_KEY = keyBuffer.slice(0, 32); 
  if (keyBuffer.length !== 32) {
    console.warn("⚠️ WARNING: AES_SECRET_KEY was not 32 bytes. Using sliced key. Please correct your .env file.");
  }
} else {
  console.warn("⚠️ WARNING: AES_SECRET_KEY not set in .env. Generating random 32-byte key.");
  AES_KEY = crypto.randomBytes(32);
}


function encryptMessage(plainText) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, iv);
  let encrypted = cipher.update(plainText, "utf8", "hex");
  encrypted += cipher.final("hex");
  return { ciphertext: encrypted, iv: iv.toString("hex") };
}

function decryptMessage(ciphertextHex, ivHex) {
  try {
    const iv = Buffer.from(ivHex, "hex");
    if (iv.length !== 16) {
        throw new Error("Invalid IV length for AES-256-CBC.");
    }
    
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, iv);
    let decrypted = decipher.update(ciphertextHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    console.error("❌ Decryption Failed for a message:", error.message);
    return "[Message Decryption Failed - Check AES Key]";
  }
}

// ===== Upload storage (multer) - FIX FOR ENOENT ERROR =====
const uploadsDir = path.join(__dirname, "uploads");

// Guarantees the directory exists on startup
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log(`Created uploads directory at: ${uploadsDir}`);
}

const storage = multer.diskStorage({
  // Use absolute path for robustness
  destination: function (req, file, cb) {
    cb(null, path.resolve(__dirname, "uploads"));
  },
  // Use a simple, unique name to prevent issues with user-provided characters
  filename: function (req, file, cb) {
    const tempId = Date.now() + "-" + crypto.randomBytes(4).toString("hex");
    const ext = path.extname(file.originalname);
    cb(null, tempId + ext);
  }
});
const upload = multer({ storage });


// ===== Routes (Authentication and API) =====

app.get("/", (req, res) => {
  if (req.session.userId) return res.redirect("/chat.html");
  res.redirect("/login.html");
});

app.post("/register", async (req, res) => {
  try {
    const existing = await User.findOne({ username: req.body.username });
    if (existing) return res.status(400).send("Username already exists");

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ username: req.body.username, password: hashedPassword });
    await user.save();
    console.log("✅ Registered:", user.username);

    req.session.userId = user._id;
    res.redirect("/login.html?registered=true");
  } catch (err) {
    console.error("❌ Registration Error:", err);
    res.status(500).send("Server error during registration");
  }
});

app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) return res.status(400).send("User not found");

    const valid = await bcrypt.compare(req.body.password, user.password);
    if (!valid) return res.status(400).send("Invalid password");

    req.session.userId = user._id;
    console.log("✅ Logged in:", user.username);
    res.redirect("/chat.html");
  } catch (err) {
    console.error("❌ Login Error:", err);
    res.status(500).send("Server error during login");
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
    if (!me) return res.status(404).json({ message: "Current user not found" });
    
    const users = await User.find({ username: { $ne: me.username } }).select("username");
    res.json(users);
  } catch (err) {
    console.error("❌ /api/users error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/messages/:other", isAuthenticated, async (req, res) => {
  try {
    const me = await User.findById(req.session.userId).select("username");
    const other = req.params.other;

    if (!me) return res.status(404).json({ message: "Current user not found" });

    const msgs = await Message.find({
      $or: [
        { sender: me.username, receiver: other },
        { sender: other, receiver: me.username },
      ],
    }).sort({ timestamp: 1 });

    const result = msgs.map((m) => {
      if (m.isFile) {
        return {
          _id: m._id,
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
          _id: m._id,
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

// ===== Upload endpoint (multipart/form-data) - Encrypts File =====
app.post("/upload", isAuthenticated, upload.single("file"), async (req, res) => {
  let tempFilePath = req.file ? req.file.path : null;
  
  try {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });
    const me = await User.findById(req.session.userId).select("username");
    const to = req.body.to;
    
    if (!me || !me.username) return res.status(401).json({ message: "Sender not authenticated" });
    if (!to) return res.status(400).json({ message: "No recipient specified" });

    // CRITICAL FIX: Normalize the path provided by Multer before reading
    tempFilePath = path.normalize(req.file.path); 
    
    // Debug log confirming the temp file path before reading
    console.log(`💾 TEMP FILE SAVED BY MULTER at: ${tempFilePath}`);
    
    const buffer = await util.promisify(fs.readFile)(tempFilePath); 
    
    // Debug log confirming the file was read successfully
    console.log(`✅ TEMP FILE READ SUCCESSFULLY: Buffer size ${buffer.length} bytes.`);

    // Encrypt file buffer
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);

    // Save the encrypted file
    const storedFileName = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}.enc`;
    const storedPath = path.join(uploadsDir, storedFileName);
    await util.promisify(fs.writeFile)(storedPath, encrypted);
    
    // Delete original temporary unencrypted file (Cleanup)
    await util.promisify(fs.unlink)(tempFilePath);

    // Create DB message row
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

    const payload = {
      _id: msg._id,
      sender: me.username,
      receiver: to,
      isFile: true,
      originalName: msg.originalName,
      mimeType: msg.mimeType,
      storedFileName: msg.storedFileName,
      timestamp: msg.timestamp,
    };

    const receiverSocketId = online.get(to);
    if (receiverSocketId) io.to(receiverSocketId).emit("fileMessage", payload);
    if (online.get(me.username)) io.to(online.get(me.username)).emit("fileMessage", payload); 

    return res.json({ success: true, payload });
  } catch (err) {
    console.error("❌ /upload error:", err);
    // Log the actual error which should now show if the failure is still ENOENT or something else
    
    if (tempFilePath && fs.existsSync(tempFilePath)) {
       // Attempt to clean up even on failure
       await util.promisify(fs.unlink)(tempFilePath).catch(e => console.error("Failed to delete temp file during error cleanup:", e));
    }
    return res.status(500).json({ message: "Upload and encryption failed on server." });
  }
});

app.get("/files/:storedFileName", isAuthenticated, async (req, res) => {
  try {
    const storedFileName = req.params.storedFileName;
    const msg = await Message.findOne({ storedFileName });
    if (!msg) return res.status(404).send("File message not found in database");

    const me = await User.findById(req.session.userId).select("username");
    
    if (me.username !== msg.sender && me.username !== msg.receiver) {
       return res.status(403).send("You are not authorized to access this file.");
    }
    
    const encPath = path.join(uploadsDir, storedFileName);
    if (!fs.existsSync(encPath)) return res.status(404).send("Encrypted file missing on server");

    const encryptedBuffer = await util.promisify(fs.readFile)(encPath);
    const iv = Buffer.from(msg.iv, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

    res.setHeader("Content-Type", msg.mimeType || "application/octet-stream");
    res.setHeader("Content-Disposition", `inline; filename="${encodeURIComponent(msg.originalName)}"`); 
    res.send(decrypted);
  } catch (err) {
    console.error("❌ /files error (Decryption/Serving Failed):", err);
    res.status(500).send("Failed to serve file due to server error");
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
      const text = data.text; // <-- Plainttext is here
      if (!from || !to || !text) return;

      const { ciphertext, iv } = encryptMessage(text);
      const msg = new Message({ sender: from, receiver: to, ciphertext, iv });
      await msg.save();

      // ===== YOUR CONCISE, REQUESTED LOGGING IS HERE (Message Encryption Proof) =====
      console.log("💾 Saved text message:", {
        from: from,
        to: to,
        ciphertext: ciphertext,
        iv: iv,
        plaintext: text, // Log the original text
      });
      // ==============================================================================

      const payload = { 
        _id: msg._id, 
        sender: from, 
        receiver: to, 
        text, 
        timestamp: msg.timestamp 
      };
      
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