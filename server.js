
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "turan2010";

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use("/uploads", express.static(UPLOAD_DIR));
app.use(express.static(__dirname));

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, Date.now() + "-" + crypto.randomBytes(6).toString("hex") + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 1024 * 1024 * 1024 }
});

const users = new Map();
const movies = [];
let nextId = 1;

function requireUser(req, res, next) {
  if (req.session.user || req.session.admin) return next();
  res.status(401).json({ error: "Əvvəlcə daxil olun." });
}

function requireAdmin(req, res, next) {
  if (req.session.admin) return next();
  res.status(403).json({ error: "Yalnız admin istifadə edə bilər." });
}

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/session", (req, res) => {
  res.json({
    user: req.session.user || null,
    isAdmin: !!req.session.admin
  });
});

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    const mail = String(email || "").trim().toLowerCase();

    if (!name || !mail || !password) {
      return res.status(400).json({ error: "Bütün xanaları doldurun." });
    }

    if (users.has(mail)) {
      return res.status(409).json({ error: "Bu hesab artıq mövcuddur." });
    }

    if (String(password).length < 8) {
      return res.status(400).json({ error: "Şifrə ən azı 8 simvol olmalıdır." });
    }

    const hash = await bcrypt.hash(String(password), 10);
    const user = { name: String(name).trim(), email: mail, hash };

    users.set(mail, user);
    req.session.user = { name: user.name, email: mail };

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Qeydiyyat alınmadı." });
  }
});

app.post("/api/login", async (req, res) => {
  const mail = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const user = users.get(mail);

  if (!user || !(await bcrypt.compare(password, user.hash))) {
    return res.status(401).json({ error: "Email və ya şifrə yanlışdır." });
  }

  req.session.user = { name: user.name, email: mail };
  req.session.admin = false;
  res.json({ ok: true });
});

app.post("/api/admin/login", (req, res) => {
  if (req.body?.password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Admin şifrəsi yanlışdır." });
  }

  req.session.user = null;
  req.session.admin = true;
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/movies", requireUser, (_req, res) => {
  res.json(movies);
});

app.post(
  "/api/movies",
  requireAdmin,
  upload.fields([
    { name: "poster", maxCount: 1 },
    { name: "video", maxCount: 1 }
  ]),
  (req, res) => {
    const poster = req.files?.poster?.[0];
    const video = req.files?.video?.[0];
    const title = String(req.body.title || "").trim();

    if (!title || !poster || !video) {
      return res.status(400).json({
        error: "Film adı, afişa və video faylı lazımdır."
      });
    }

    if (!poster.mimetype.startsWith("image/") ||
        !video.mimetype.startsWith("video/")) {
      return res.status(400).json({
        error: "Afişa şəkil, film isə video faylı olmalıdır."
      });
    }

    const movie = {
      id: nextId++,
      title,
      year: req.body.year || "",
      country: req.body.country || "",
      genre: req.body.genre || "",
      desc: req.body.desc || "",
      poster: "/uploads/" + poster.filename,
      video: "/uploads/" + video.filename
    };

    movies.unshift(movie);
    res.json({ ok: true, movie });
  }
);

app.delete("/api/movies/:id", requireAdmin, (req, res) => {
  const index = movies.findIndex(m => m.id === Number(req.params.id));

  if (index < 0) {
    return res.status(404).json({ error: "Film tapılmadı." });
  }

  const movie = movies.splice(index, 1)[0];

  for (const url of [movie.poster, movie.video]) {
    fs.promises.unlink(
      path.join(UPLOAD_DIR, path.basename(url))
    ).catch(() => {});
  }

  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("Qəşəy Film serveri başladı: " + PORT);
});
