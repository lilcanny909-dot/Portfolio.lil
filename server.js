import crypto from "crypto";
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

let sock = null;
let waReady = false;
let pairingRequested = false;

const pendingOtps = new Map();
const users = new Map();

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

    // Trigger pairing code when unregistered (no QR code generated)
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

// Sign Up: Generate OTP & send via WhatsApp to the phone number entered by the user
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

// Verify OTP & create account
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

  users.set(targetPhone, {
    ...record.user,
    verified: true
  });
  pendingOtps.delete(targetPhone);

  return res.json({
    ok: true,
    user: { phone: targetPhone, email: record.user.email }
  });
});

// Log In
app.post("/api/auth/login", (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ error: "Enter your phone/email and password." });
  }

  const normalized = normalizePhone(identifier);
  const queryEmail = String(identifier).trim().toLowerCase();
  const pwdHash = hashPassword(password);

  let matchedUser = users.get(normalized);
  if (!matchedUser) {
    for (const u of users.values()) {
      if (u.email === queryEmail) {
        matchedUser = u;
        break;
      }
    }
  }

  if (!matchedUser || !matchedUser.verified || matchedUser.passwordHash !== pwdHash) {
    return res.status(401).json({ error: "Invalid login credentials." });
  }

  return res.json({
    ok: true,
    user: { phone: matchedUser.phone, email: matchedUser.email }
  });
});

startWhatsApp();
app.listen(PORT, () => {
  console.log(`Live server listening on port ${PORT}`);
});
