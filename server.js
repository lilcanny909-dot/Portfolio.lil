import crypto from "crypto";
import fs from "fs";
import path from "path";
import express from "express";
import cors from "cors";
import pino from "pino";
import makeWASocket, {
  DisconnectReason,
  useMultiFileAuthState
} from "@whiskeysockets/baileys";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;
const PAIRING_PHONE = "2347084758045";
const DATA_FILE = path.resolve("./store_data.json");

let sock = null;
let waReady = false;
let pairingRequested = false;

const pendingOtps = new Map();

function loadStore() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    }
  } catch (err) {
    console.error("Failed to read store_data.json:", err.message);
  }
  return { users: {}, tradesByUser: {} };
}

function saveStore(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error("Failed to write store_data.json:", err.message);
  }
}

const store = loadStore();

function normalizePhone(raw) {
  const digits = String(raw || "").replace(/\D/g, "");
  if (digits.startsWith("0") && digits.length === 11) {
    return "234" + digits.slice(1);
  }
  return digits;
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function generateOtp() {
  return String(crypto.randomInt(100000, 999999));
}

function createToken(phone) {
  return crypto.createHmac("sha256", process.env.SESSION_SECRET || "fx-terminal-secret")
    .update(`${phone}:${Date.now()}`)
    .digest("hex");
}

async function startWhatsApp() {
  pairingRequested = false;
  waReady = false;

  const { state, saveCreds } = await useMultiFileAuthState("./auth_session_2347084758045");

  sock = makeWASocket({
    auth: state,
    logger: pino({ level: "silent" }),
    browser: ["Ubuntu", "Chrome", "20.0.04"],
    printQRInTerminal: false
  });

  sock.ev.on("creds.update", saveCreds);

  sock.ev.on("connection.update", async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr && !sock.authState.creds.registered && !pairingRequested) {
      pairingRequested = true;
      try {
        await new Promise((resolve) => setTimeout(resolve, 1500));
        const code = await sock.requestPairingCode(PAIRING_PHONE);
        console.log("==========================================");
        console.log(`WHATSAPP PAIRING CODE (${PAIRING_PHONE}): ${code}`);
        console.log("Open WhatsApp -> Linked Devices -> Link with phone number");
        console.log("==========================================");
      } catch (err) {
        pairingRequested = false;
        console.error("Failed to generate pairing code:", err.message);
      }
    }

    if (connection === "open") {
      waReady = true;
      pairingRequested = false;
      console.log(`WhatsApp connected and ready on +${PAIRING_PHONE}`);
    }

    if (connection === "close") {
      waReady = false;
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const shouldReconnect = statusCode !== DisconnectReason.loggedOut;
      console.log("WhatsApp connection closed. Status:", statusCode, "| Reconnect:", shouldReconnect);
      if (shouldReconnect) {
        setTimeout(startWhatsApp, 2500);
      }
    }
  });
}

// Step 1: Sign up & send OTP via WhatsApp
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    const targetPhone = normalizePhone(phone);

    if (!targetPhone || targetPhone.length < 10 || !email || !password || password.length < 6) {
      return res.status(400).json({
        error: "Enter a valid phone number, email, and password (minimum 6 characters)."
      });
    }

    if (!sock || !waReady) {
      return res.status(503).json({
        error: `WhatsApp sender (+${PAIRING_PHONE}) is not linked yet. Check server logs for the pairing code.`
      });
    }

    const otp = generateOtp();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    const jid = `${targetPhone}@s.whatsapp.net`;

    await sock.sendMessage(jid, {
      text: `Your verification OTP is *${otp}*.\nValid for 5 minutes.`
    });

    pendingOtps.set(targetPhone, {
      code: otp,
      expiresAt,
      user: {
        phone: targetPhone,
        email: email.trim().toLowerCase(),
        passwordHash: hashPassword(password)
      }
    });

    return res.json({
      ok: true,
      phone: targetPhone,
      message: `OTP sent via WhatsApp to +${targetPhone}`
    });
  } catch (err) {
    console.error("Error sending OTP:", err);
    return res.status(500).json({ error: "Could not send WhatsApp OTP." });
  }
});

// Step 2: Verify OTP & create account
app.post("/api/auth/verify-otp", (req, res) => {
  const { phone, otp } = req.body;
  const targetPhone = normalizePhone(phone);
  const record = pendingOtps.get(targetPhone);

  if (!record) {
    return res.status(400).json({ error: "No OTP request found for this number." });
  }
  if (Date.now() > record.expiresAt) {
    pendingOtps.delete(targetPhone);
    return res.status(400).json({ error: "OTP has expired. Request a new code." });
  }
  if (record.code !== String(otp || "").trim()) {
    return res.status(400).json({ error: "Incorrect OTP code." });
  }

  const token = createToken(targetPhone);
  store.users[targetPhone] = {
    ...record.user,
    verified: true,
    token
  };
  if (!store.tradesByUser[targetPhone]) {
    store.tradesByUser[targetPhone] = [];
  }
  saveStore(store);
  pendingOtps.delete(targetPhone);

  return res.json({
    ok: true,
    token,
    user: { phone: targetPhone, email: record.user.email },
    trades: store.tradesByUser[targetPhone]
  });
});

// Step 3: Log In
app.post("/api/auth/login", (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ error: "Enter your phone/email and password." });
  }

  const normalized = normalizePhone(identifier);
  const queryEmail = String(identifier).trim().toLowerCase();
  const pwdHash = hashPassword(password);

  let matchedUser = store.users[normalized];
  if (!matchedUser) {
    matchedUser = Object.values(store.users).find((u) => u.email === queryEmail);
  }

  if (!matchedUser || !matchedUser.verified || matchedUser.passwordHash !== pwdHash) {
    return res.status(401).json({ error: "Invalid login credentials." });
  }

  const token = matchedUser.token || createToken(matchedUser.phone);
  matchedUser.token = token;
  if (!store.tradesByUser[matchedUser.phone]) {
    store.tradesByUser[matchedUser.phone] = [];
  }
  saveStore(store);

  return res.json({
    ok: true,
    token,
    user: { phone: matchedUser.phone, email: matchedUser.email },
    trades: store.tradesByUser[matchedUser.phone]
  });
});

// Session restore on reload
app.get("/api/session", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Not authenticated" });

  const user = Object.values(store.users).find((u) => u.token === token);
  if (!user) return res.status(401).json({ error: "Invalid session" });

  return res.json({
    ok: true,
    user: { phone: user.phone, email: user.email },
    trades: store.tradesByUser[user.phone] || []
  });
});

// Save user's trades
app.put("/api/trades", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const user = Object.values(store.users).find((u) => u.token === token);
  if (!user) return res.status(401).json({ error: "Not authenticated" });

  const incomingTrades = Array.isArray(req.body.trades) ? req.body.trades : [];
  store.tradesByUser[user.phone] = incomingTrades;
  saveStore(store);

  return res.json({ ok: true, trades: store.tradesByUser[user.phone] });
});

startWhatsApp();
app.listen(PORT, () => {
  console.log(`Live server listening on port ${PORT}`);
});
