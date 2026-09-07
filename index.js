const jsonServer = require('json-server');
const nodemailer = require('nodemailer');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const scryptAsync = promisify(crypto.scrypt);

const server = jsonServer.create();

// En Render, DATA_FILE puede apuntar a un disco persistente, por ejemplo:
// /opt/render/project/src/data/almacen.json
const seedDataFile = path.join(__dirname, 'almacen.json');
const dataFile = process.env.DATA_FILE ? path.resolve(process.env.DATA_FILE) : seedDataFile;

if (dataFile !== seedDataFile && !fs.existsSync(dataFile)) {
  fs.mkdirSync(path.dirname(dataFile), { recursive: true });
  fs.copyFileSync(seedDataFile, dataFile);
}

const router = jsonServer.router(dataFile);
const db = router.db;
const port = Number(process.env.PORT || 10000);

server.set('trust proxy', 1);

const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const SESSION_COOKIE = 'repodata_session';
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000; // 8 horas
const RESET_TOKEN_DURATION_MS = 15 * 60 * 1000; // 15 minutos
const PASSWORD_MIN_LENGTH = 8;
const MAX_BODY_STRING = 4000;

const defaultOrigins = [
  'http://localhost:4200',
  'http://localhost:8100',
  'http://localhost',
  'https://localhost',
  'capacitor://localhost',
  'ionic://localhost',
];

const allowedOrigins = (process.env.CORS_ORIGINS || defaultOrigins.join(','))
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

function isAllowedOrigin(origin) {
  return !origin || allowedOrigins.includes(origin);
}

server.use((req, res, next) => {
  // Cabeceras de seguridad para una API JSON.
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (IS_PRODUCTION) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

server.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

server.use(cors({
  origin(origin, callback) {
    if (isAllowedOrigin(origin)) return callback(null, true);
    return callback(new Error('Origen no permitido por CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept'],
  maxAge: 600,
}));

server.use(jsonServer.bodyParser);

// Defensa CSRF para la cookie HttpOnly: los cambios de estado solo se aceptan
// desde orígenes explícitamente autorizados.
server.use((req, res, next) => {
  const safeMethod = ['GET', 'HEAD', 'OPTIONS'].includes(req.method);
  if (safeMethod) return next();

  const origin = req.get('origin');
  if (origin && !isAllowedOrigin(origin)) {
    return res.status(403).json({ message: 'Origen no autorizado.' });
  }
  next();
});

// Evita que json-server exponga la base completa o las sesiones internas.
server.use('/db', (_req, res) => res.status(404).json({ message: 'No encontrado.' }));
server.all(/^\/sessions(?:\/.*)?$/, (_req, res) => {
  res.status(404).json({ message: 'No encontrado.' });
});

function normalizeString(value, max = 255) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}

function normalizeEmail(value) {
  return normalizeString(value, 254).toLowerCase();
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isValidPassword(password) {
  return (
    typeof password === 'string' &&
    password.length >= PASSWORD_MIN_LENGTH &&
    password.length <= 128 &&
    /[A-Za-zÁÉÍÓÚáéíóúÑñ]/.test(password) &&
    /\d/.test(password)
  );
}

function sanitizeUser(user) {
  if (!user) return null;
  const {
    password,
    resetToken,
    resetTokenHash,
    resetTokenExpiresAt,
    sessionVersion,
    ...safeUser
  } = user;
  return safeUser;
}

function parseCookies(header = '') {
  return header.split(';').reduce((acc, chunk) => {
    const separator = chunk.indexOf('=');
    if (separator === -1) return acc;
    const key = chunk.slice(0, separator).trim();
    const value = chunk.slice(separator + 1).trim();
    if (!key) return acc;
    try {
      acc[key] = decodeURIComponent(value);
    } catch {
      acc[key] = value;
    }
    return acc;
  }, {});
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEY_LENGTH = 64;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, SCRYPT_KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });

  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt}$${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
  if (typeof storedHash !== 'string' || !storedHash.startsWith('scrypt$')) {
    return false;
  }

  const parts = storedHash.split('$');
  if (parts.length !== 6) return false;

  const [, nRaw, rRaw, pRaw, salt, expectedHex] = parts;
  const N = Number(nRaw);
  const r = Number(rRaw);
  const p = Number(pRaw);

  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  if (!/^[0-9a-f]+$/i.test(expectedHex) || expectedHex.length !== SCRYPT_KEY_LENGTH * 2) return false;

  const actual = await scryptAsync(password, salt, SCRYPT_KEY_LENGTH, {
    N,
    r,
    p,
    maxmem: 64 * 1024 * 1024,
  });
  const expected = Buffer.from(expectedHex, 'hex');

  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function setSessionCookie(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: IS_PRODUCTION ? 'none' : 'lax',
    path: '/',
    maxAge: SESSION_DURATION_MS,
  });
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: IS_PRODUCTION ? 'none' : 'lax',
    path: '/',
  });
}

function createRateLimiter({ windowMs, max }) {
  const hits = new Map();

  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip || req.socket.remoteAddress || 'unknown';
    const previous = hits.get(key);

    if (!previous || now >= previous.resetAt) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    previous.count += 1;
    if (previous.count > max) {
      const retryAfter = Math.ceil((previous.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ message: 'Demasiadas solicitudes. Intenta nuevamente más tarde.' });
    }

    // Limpieza ocasional para evitar crecimiento indefinido del Map.
    if (hits.size > 5000) {
      for (const [storedKey, entry] of hits.entries()) {
        if (now >= entry.resetAt) hits.delete(storedKey);
      }
    }

    next();
  };
}

const authLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10 });
const recoverLimiter = createRateLimiter({ windowMs: 30 * 60 * 1000, max: 5 });

async function createSession(userId) {
  const rawToken = crypto.randomBytes(32).toString('base64url');
  const tokenHash = sha256(rawToken);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();

  const sessions = db.get('sessions');
  sessions
    .remove((session) => session.userId === userId || new Date(session.expiresAt).getTime() <= Date.now())
    .write();

  sessions.push({
    id: crypto.randomUUID(),
    tokenHash,
    userId,
    expiresAt,
    createdAt: new Date().toISOString(),
  }).write();

  return rawToken;
}

function deleteSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const rawToken = cookies[SESSION_COOKIE];
  if (!rawToken) return;
  db.get('sessions').remove({ tokenHash: sha256(rawToken) }).write();
}

async function requireAuth(req, res, next) {
  try {
    const cookies = parseCookies(req.headers.cookie || '');
    const rawToken = cookies[SESSION_COOKIE];
    if (!rawToken) {
      return res.status(401).json({ message: 'Debes iniciar sesión.' });
    }

    const tokenHash = sha256(rawToken);
    const session = db.get('sessions').find({ tokenHash }).value();

    if (!session || new Date(session.expiresAt).getTime() <= Date.now()) {
      if (session) db.get('sessions').remove({ tokenHash }).write();
      clearSessionCookie(res);
      return res.status(401).json({ message: 'Sesión inválida o expirada.' });
    }

    const user = db.get('usuarios').find({ id: session.userId }).value();
    if (!user || user.isactive !== true) {
      db.get('sessions').remove({ tokenHash }).write();
      clearSessionCookie(res);
      return res.status(401).json({ message: 'Sesión inválida.' });
    }

    req.user = user;
    req.sessionRecord = session;
    next();
  } catch (error) {
    console.error('Error validando sesión:', error.message);
    res.status(500).json({ message: 'No fue posible validar la sesión.' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ message: 'No tienes permisos para realizar esta acción.' });
  }
  next();
}

function getSmtpTransporter() {
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!user || !pass) return null;

  return nodemailer.createTransport({
    service: process.env.SMTP_SERVICE || 'gmail',
    auth: { user, pass },
  });
}

// -----------------------------
// Autenticación
// -----------------------------

server.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const username = normalizeString(req.body?.username, 80);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!username || password.length === 0 || password.length > 128) {
      return res.status(400).json({ message: 'Solicitud inválida.' });
    }

    const user = db.get('usuarios').find({ username }).value();

    // Se calcula un hash ficticio cuando el usuario no existe para reducir diferencias
    // de tiempo que faciliten enumerar usuarios.
    const dummyHash = 'scrypt$16384$8$1$0123456789abcdef0123456789abcdef$' + '00'.repeat(64);
    const validPassword = await verifyPassword(password, user?.password || dummyHash);

    if (!user || !validPassword) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos.' });
    }

    if (user.isactive !== true) {
      return res.status(403).json({ message: 'La cuenta no se encuentra activa.' });
    }

    deleteSessionFromRequest(req);
    const token = await createSession(user.id);
    setSessionCookie(res, token);
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ user: sanitizeUser(user) });
  } catch (error) {
    console.error('Error en login:', error.message);
    return res.status(500).json({ message: 'No fue posible iniciar sesión.' });
  }
});

server.get('/auth/me', requireAuth, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json(sanitizeUser(req.user));
});

server.post('/auth/logout', requireAuth, (req, res) => {
  if (req.sessionRecord) {
    db.get('sessions').remove({ id: req.sessionRecord.id }).write();
  }
  clearSessionCookie(res);
  res.status(204).end();
});

// -----------------------------
// Usuarios
// -----------------------------

server.post('/usuarios', authLimiter, async (req, res) => {
  try {
    const username = normalizeString(req.body?.username, 80);
    const email = normalizeEmail(req.body?.email);
    const pnombre = normalizeString(req.body?.pnombre, 80);
    const apellido = normalizeString(req.body?.apellido, 80);
    const carrera = normalizeString(req.body?.carrera, 120);
    const password = req.body?.password;
    const rut = Number(req.body?.rut);

    if (
      username.length < 6 ||
      !isValidEmail(email) ||
      !pnombre ||
      !apellido ||
      !Number.isInteger(rut) ||
      rut < 1000000 ||
      rut > 99999999 ||
      !isValidPassword(password)
    ) {
      return res.status(400).json({ message: 'Datos de registro inválidos.' });
    }

    const users = db.get('usuarios').value();
    const duplicated = users.some((u) =>
      String(u.username).toLowerCase() === username.toLowerCase() ||
      String(u.email).toLowerCase() === email ||
      Number(u.rut) === rut
    );

    if (duplicated) {
      return res.status(409).json({ message: 'El usuario, correo o RUT ya está registrado.' });
    }

    const newUser = {
      id: crypto.randomUUID(),
      rut,
      username,
      email,
      pnombre,
      apellido,
      carrera,
      password: await hashPassword(password),
      isactive: true,
      role: 'user', // Nunca se acepta role desde el cliente.
      resetTokenHash: null,
      resetTokenExpiresAt: null,
      createdAt: new Date().toISOString(),
    };

    db.get('usuarios').push(newUser).write();
    return res.status(201).json(sanitizeUser(newUser));
  } catch (error) {
    console.error('Error registrando usuario:', error.message);
    return res.status(500).json({ message: 'No fue posible crear la cuenta.' });
  }
});

server.get('/usuarios', requireAuth, requireAdmin, (_req, res) => {
  const users = db.get('usuarios').value().map(sanitizeUser);
  res.json(users);
});

server.put('/usuarios/me', requireAuth, (req, res) => {
  const username = normalizeString(req.body?.username, 80);
  const email = normalizeEmail(req.body?.email);
  const pnombre = normalizeString(req.body?.pnombre, 80);
  const apellido = normalizeString(req.body?.apellido, 80);
  const carrera = normalizeString(req.body?.carrera, 120);
  const rut = Number(req.body?.rut);

  if (
    username.length < 6 ||
    !isValidEmail(email) ||
    !pnombre ||
    !apellido ||
    !Number.isInteger(rut) ||
    rut < 1000000 ||
    rut > 99999999
  ) {
    return res.status(400).json({ message: 'Datos de perfil inválidos.' });
  }

  const users = db.get('usuarios').value();
  const duplicated = users.some((u) =>
    u.id !== req.user.id && (
      String(u.username).toLowerCase() === username.toLowerCase() ||
      String(u.email).toLowerCase() === email ||
      Number(u.rut) === rut
    )
  );

  if (duplicated) {
    return res.status(409).json({ message: 'El usuario, correo o RUT ya está registrado.' });
  }

  const updated = db.get('usuarios')
    .find({ id: req.user.id })
    .assign({ username, email, pnombre, apellido, carrera, rut, updatedAt: new Date().toISOString() })
    .write();

  res.json(sanitizeUser(updated));
});

// Bloquea cualquier otra ruta CRUD de usuarios para que json-server nunca
// devuelva password/hash/resetToken ni permita modificar role/isactive por ID.
server.all(/^\/usuarios(?:\/.*)?$/, (_req, res) => {
  res.status(404).json({ message: 'Ruta no disponible.' });
});

// -----------------------------
// Recuperación de contraseña
// -----------------------------

server.post('/recover-password', recoverLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'Correo inválido.' });
    }

    const genericResponse = { message: 'Si el correo está registrado, recibirás instrucciones de recuperación.' };
    const user = db.get('usuarios').find((u) => String(u.email).toLowerCase() === email).value();

    // No revelar si el correo existe.
    if (!user) return res.json(genericResponse);

    const transporter = getSmtpTransporter();
    if (!transporter) {
      console.error('SMTP_USER/SMTP_PASS no están configurados.');
      return res.status(503).json({ message: 'El servicio de correo no está disponible.' });
    }

    const rawToken = crypto.randomBytes(32).toString('base64url');
    const tokenHash = sha256(rawToken);
    const expiresAt = new Date(Date.now() + RESET_TOKEN_DURATION_MS).toISOString();

    db.get('usuarios').find({ id: user.id }).assign({
      resetTokenHash: tokenHash,
      resetTokenExpiresAt: expiresAt,
    }).write();

    await transporter.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to: email,
      subject: 'Recuperación de contraseña',
      text: `Tu token de recuperación es: ${rawToken}\n\nExpira en 15 minutos y solo puede utilizarse una vez.`,
    });

    return res.json(genericResponse);
  } catch (error) {
    console.error('Error enviando recuperación:', error.message);
    return res.status(500).json({ message: 'No fue posible procesar la recuperación.' });
  }
});

server.post('/reset-password', recoverLimiter, async (req, res) => {
  try {
    const token = normalizeString(req.body?.token, 200);
    const newPassword = req.body?.newPassword;

    if (!token || !isValidPassword(newPassword)) {
      return res.status(400).json({ message: 'Token o contraseña inválidos.' });
    }

    const tokenHash = sha256(token);
    const user = db.get('usuarios').find({ resetTokenHash: tokenHash }).value();

    if (!user || !user.resetTokenExpiresAt || new Date(user.resetTokenExpiresAt).getTime() <= Date.now()) {
      return res.status(400).json({ message: 'Token inválido o expirado.' });
    }

    const newHash = await hashPassword(newPassword);
    db.get('usuarios').find({ id: user.id }).assign({
      password: newHash,
      resetTokenHash: null,
      resetTokenExpiresAt: null,
      passwordChangedAt: new Date().toISOString(),
    }).write();

    // Cierra todas las sesiones activas después de cambiar la contraseña.
    db.get('sessions').remove({ userId: user.id }).write();

    return res.json({ message: 'Contraseña actualizada correctamente.' });
  } catch (error) {
    console.error('Error restableciendo contraseña:', error.message);
    return res.status(500).json({ message: 'No fue posible actualizar la contraseña.' });
  }
});

// -----------------------------
// Eventos
// -----------------------------

// Toda lectura/escritura de eventos requiere una sesión real.
server.use('/eventos', requireAuth);

// Para no romper el comportamiento existente, cualquier usuario autenticado y
// activo puede administrar eventos. Si tu aplicación distingue administradores,
// cambia este middleware por requireAdmin para POST/PUT/PATCH/DELETE.
server.use('/eventos', (req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    // Whitelisting adicional se aplica en las rutas específicas de abajo.
  }
  next();
});

server.post('/eventos', (req, res) => {
  const nombre = normalizeString(req.body?.nombre, 150);
  const lugar = normalizeString(req.body?.lugar, 150);
  const anfitrion = normalizeString(req.body?.anfitrion, 150);
  const descripcion = normalizeString(req.body?.descripcion, MAX_BODY_STRING);
  const fecha = normalizeString(req.body?.fecha, 30);
  const cupos = Number(req.body?.cupos);

  if (!nombre || !lugar || !anfitrion || descripcion.length < 20 || !fecha || !Number.isInteger(cupos) || cupos < 1 || cupos > 100000) {
    return res.status(400).json({ message: 'Datos del evento inválidos.' });
  }

  const event = {
    id: crypto.randomUUID(),
    nombre,
    lugar,
    cupos,
    fecha,
    anfitrion,
    descripcion,
    asistentes: [],
    comentarios: [],
    createdBy: req.user.id,
    createdAt: new Date().toISOString(),
  };

  db.get('eventos').push(event).write();
  res.status(201).json(event);
});

server.put('/eventos/:id', (req, res) => {
  const event = db.get('eventos').find({ id: req.params.id }).value();
  if (!event) return res.status(404).json({ message: 'Evento no encontrado.' });

  const nombre = normalizeString(req.body?.nombre, 150);
  const lugar = normalizeString(req.body?.lugar, 150);
  const anfitrion = normalizeString(req.body?.anfitrion, 150);
  const descripcion = normalizeString(req.body?.descripcion, MAX_BODY_STRING);
  const fecha = normalizeString(req.body?.fecha, 30);
  const cupos = Number(req.body?.cupos);

  if (!nombre || !lugar || !anfitrion || descripcion.length < 20 || !fecha || !Number.isInteger(cupos) || cupos < 1 || cupos > 100000) {
    return res.status(400).json({ message: 'Datos del evento inválidos.' });
  }

  const updated = db.get('eventos').find({ id: req.params.id }).assign({
    nombre,
    lugar,
    anfitrion,
    descripcion,
    fecha,
    cupos,
    updatedAt: new Date().toISOString(),
  }).write();

  res.json(updated);
});

server.delete('/eventos/:id', (req, res) => {
  const event = db.get('eventos').find({ id: req.params.id }).value();
  if (!event) return res.status(404).json({ message: 'Evento no encontrado.' });

  db.get('eventos').remove({ id: req.params.id }).write();
  res.status(204).end();
});

// No permitir PATCH u otros métodos genéricos de json-server sobre eventos,
// porque podrían modificar asistentes/createdBy u otros campos internos.
server.all(/^\/eventos(?:\/.*)?$/, (req, res, next) => {
  if (['GET', 'HEAD'].includes(req.method)) return next();
  return res.status(405).json({ message: 'Método no permitido.' });
});

server.get('/:eventId/asistentes', requireAuth, (req, res) => {
  const event = db.get('eventos').find({ id: req.params.eventId }).value();
  if (!event) return res.status(404).json({ message: 'Evento no encontrado.' });
  res.json(event.asistentes || []);
});

// -----------------------------
// QR seguro
// -----------------------------

// Emite un token opaco. El QR debe contener SOLO el token devuelto.
server.post('/QR/issue', requireAuth, (req, res) => {
  const eventoId = normalizeString(req.body?.eventoId, 100);
  const event = db.get('eventos').find({ id: eventoId }).value();
  if (!event) return res.status(404).json({ message: 'Evento no encontrado.' });

  const rawToken = crypto.randomBytes(32).toString('base64url');
  const qrRecord = {
    id: crypto.randomUUID(),
    tokenHash: sha256(rawToken),
    eventoId,
    userId: req.user.id,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    usedAt: null,
  };

  db.get('QR').push(qrRecord).write();
  res.status(201).json({ token: rawToken, expiresAt: qrRecord.expiresAt });
});

server.post('/QR/validate', requireAuth, (req, res) => {
  const token = normalizeString(req.body?.token, 2048);
  if (token.length < 20) {
    return res.status(400).json({ message: 'QR inválido.' });
  }

  const qrRecord = db.get('QR').find({ tokenHash: sha256(token) }).value();
  if (!qrRecord) return res.status(400).json({ message: 'QR inválido.' });
  if (qrRecord.usedAt) return res.status(409).json({ message: 'Este QR ya fue utilizado.' });
  if (new Date(qrRecord.expiresAt).getTime() <= Date.now()) {
    return res.status(400).json({ message: 'El QR expiró.' });
  }

  const event = db.get('eventos').find({ id: qrRecord.eventoId }).value();
  const attendee = db.get('usuarios').find({ id: qrRecord.userId }).value();
  if (!event || !attendee) return res.status(400).json({ message: 'QR inválido.' });

  const alreadyRegistered = (event.asistentes || []).some((a) => a.userId === attendee.id || a.username === attendee.username);
  if (!alreadyRegistered) {
    const asistentes = [...(event.asistentes || []), {
      userId: attendee.id,
      username: attendee.username,
      estado: 'registrado',
      registradoAt: new Date().toISOString(),
    }];
    db.get('eventos').find({ id: event.id }).assign({ asistentes }).write();
  }

  db.get('QR').find({ id: qrRecord.id }).assign({ usedAt: new Date().toISOString() }).write();

  res.json({
    message: alreadyRegistered ? 'El usuario ya estaba registrado en el evento.' : 'Asistencia registrada correctamente.',
    evento: { id: event.id, nombre: event.nombre },
    usuario: { id: attendee.id, username: attendee.username, pnombre: attendee.pnombre, apellido: attendee.apellido },
  });
});

// Nunca exponer la colección QR completa ni permitir CRUD genérico sobre ella.
server.all(/^\/QR(?:\/.*)?$/, (_req, res) => {
  res.status(404).json({ message: 'Ruta no disponible.' });
});

// -----------------------------
// JSON Server solo queda como lectura segura de rutas no sensibles.
// -----------------------------

server.get('/', (_req, res) => {
  res.json({ service: 'repodata', status: 'ok' });
});

server.use(router);

// Error CORS u otros errores de middleware.
server.use((error, _req, res, _next) => {
  console.error('Error de servidor:', error.message);
  res.status(500).json({ message: 'Error interno del servidor.' });
});

async function migrateDatabase() {
  if (!db.has('sessions').value()) db.set('sessions', []).write();
  if (!db.has('QR').value()) db.set('QR', []).write();
  if (!db.has('eventos').value()) db.set('eventos', []).write();
  if (!db.has('usuarios').value()) db.set('usuarios', []).write();

  const users = db.get('usuarios').value();
  let changed = false;

  for (const user of users) {
    // Migración automática de las contraseñas antiguas en texto plano.
    if (typeof user.password === 'string' && !user.password.startsWith('scrypt$')) {
      user.password = await hashPassword(user.password);
      changed = true;
    }

    // Campos antiguos de recuperación ya no son válidos.
    if (Object.prototype.hasOwnProperty.call(user, 'resetToken')) {
      delete user.resetToken;
      changed = true;
    }
    if (!Object.prototype.hasOwnProperty.call(user, 'resetTokenHash')) {
      user.resetTokenHash = null;
      changed = true;
    }
    if (!Object.prototype.hasOwnProperty.call(user, 'resetTokenExpiresAt')) {
      user.resetTokenExpiresAt = null;
      changed = true;
    }
    if (!user.role) {
      user.role = 'user';
      changed = true;
    }
  }

  // Permite designar un administrador existente sin aceptar roles desde el cliente.
  const bootstrapAdmin = normalizeString(process.env.BOOTSTRAP_ADMIN_USERNAME, 80);
  if (bootstrapAdmin) {
    const admin = users.find((u) => u.username === bootstrapAdmin);
    if (admin && admin.role !== 'admin') {
      admin.role = 'admin';
      changed = true;
      console.log(`Rol admin aplicado a ${bootstrapAdmin}.`);
    }
  }

  if (changed) db.set('usuarios', users).write();

  // Las sesiones no deben sobrevivir indefinidamente.
  db.get('sessions').remove((session) => new Date(session.expiresAt).getTime() <= Date.now()).write();
}

migrateDatabase()
  .then(() => {
    server.listen(port, '0.0.0.0', () => {
      console.log(`Servidor seguro ejecutándose en el puerto ${port}`);
      console.log(`Orígenes CORS permitidos: ${allowedOrigins.join(', ')}`);
    });
  })
  .catch((error) => {
    console.error('No fue posible iniciar el servidor:', error);
    process.exit(1);
  });
