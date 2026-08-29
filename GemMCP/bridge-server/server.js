const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { exec, execFile } = require('child_process');
const crypto = require('crypto');
const { createFileActions } = require('./actions-files');
const { handleWindowsExecute } = require('./windows-handler');
const { cancelJob: cancelInstallJob, listJobs: listInstallJobs } = require('./install-jobs');
const { runPlan, MAX_STEPS } = require('./plan-runner');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config({ path: path.join(__dirname, '.env') });

process.on('uncaughtException', (err) => {
  console.error('⚠️ [Bridge Server Uncaught Exception]:', err.message);
});

process.on('unhandledRejection', (reason) => {
  console.error('⚠️ [Bridge Server Unhandled Rejection]:', reason);
});

const app = express();
// פורט מאומת: מתעלם מערכים לא תקינים (0, ריק, לא מספר) כדי להבטיח שהשרת תמיד עולה על פורט אמיתי
const rawPort = Number(process.env.PORT);
const PORT = Number.isInteger(rawPort) && rawPort > 0 ? rawPort : 3000;
const HOST = '127.0.0.1'; // נעילת שרת ל-localhost בלבד למניעת חשיפה ברשת

// הגדרת CORS מאובטחת - מאשר רק את תוסף הכרום, Localhost, ו-Gemini
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (origin.startsWith('chrome-extension://')) return callback(null, true);
    // הדף של ג'מיני אינו ברשימה בכוונה. מדיניות Local Network Access חוסמת
    // ממילא גישה מהקשר הדף ל-localhost, ולכן היתר כזה אינו מאפשר שום דבר
    // שעובד היום - אבל אם המדיניות תשתנה, כל סקריפט שרץ בדף היה מקבל גישה
    // ישירה לגשר. הפקודות מגיעות דרך ה-service worker, שהמקור שלו הוא
    // chrome-extension:// ומכוסה בשורה שמעל.
    try {
      const host = new URL(origin).hostname;
      if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]') {
        return callback(null, true);
      }
    } catch (e) { /* origin לא תקין - ייפול לחסימה */ }
    return callback(new Error('גישה נחסמה מטעמי אבטחה (CORS Policy). הבקשה אינה מגיעה ממקור מאושר.'));
  }
};

app.use(cors(corsOptions));
app.use(express.json());

// ---------------------------------------------------------------------------
// אימות
//
// במקור האימות היה בלתי שמיש: התוסף לא שלח את הכותרת x-bridge-token, ולכן
// הפעלת BRIDGE_AUTH_TOKEN פשוט שברה אותו. עכשיו התוסף שולח אותה, והמנגנון
// עובד - אך נשאר אופציונלי, מהסיבה שמוסברת ליד AUTH_TOKEN.
// ---------------------------------------------------------------------------
const PROTOCOL_VERSION = 1;

// הטוקן הוא הגנה אופציונלית, ומופעל רק אם הוגדר במפורש ב-.env.
//
// למה לא חובה: ב-Windows ה-ACL של קובץ הטוקן פתוח לכל תהליך של אותו משתמש
// (mode 0o600 של Node הוא no-op כאן), ולכן טוקן בקובץ אינו מונע מתהליך מקומי
// זדוני להשתמש בגשר - הוא רק הוסיף שלב ידני למשתמש. מה שהוא כן חוסם הוא דף
// אינטרנט, שאינו יכול לקרוא קבצים - וזה מכוסה ממילא בבדיקת ה-Origin ב-CORS.
// מי שרוצה את השכבה הנוספת מגדיר BRIDGE_AUTH_TOKEN ב-.env, וזה נאכף במלואו.
const AUTH_TOKEN = (process.env.BRIDGE_AUTH_TOKEN || '').trim();
const AUTH_REQUIRED = AUTH_TOKEN.length > 0;

// נתיבים שמותר לפנות אליהם בלי טוקן: בדיקת בריאות (כדי שהתוסף יוכל לזהות שהשרת
// חי ולהציג הוראות), ודף ה-callback של OAuth שהדפדפן מגיע אליו בניווט רגיל.
const OPEN_PATHS = new Set(['/api/health', '/oauth/callback']);

// הגבלת קצב פשוטה: חלון מתגלגל לכל כתובת מקור. מונע לופ של מודל שמשתגע ומונע
// מסקריפט מקומי להציף את ה-endpoint.
const RATE_LIMIT_WINDOW_MS = 10000;
const RATE_LIMIT_MAX = 40;
const rateBuckets = new Map();

function checkRateLimit(key) {
  const now = Date.now();
  const bucket = (rateBuckets.get(key) || []).filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  bucket.push(now);
  rateBuckets.set(key, bucket);
  if (rateBuckets.size > 256) {
    for (const [k, v] of rateBuckets) {
      if (!v.length || now - v[v.length - 1] > RATE_LIMIT_WINDOW_MS) rateBuckets.delete(k);
    }
  }
  return bucket.length <= RATE_LIMIT_MAX;
}

app.use((req, res, next) => {
  if (!checkRateLimit(req.ip || 'local')) {
    return res.status(429).json({
      success: false,
      error: `יותר מ-${RATE_LIMIT_MAX} בקשות ב-${RATE_LIMIT_WINDOW_MS / 1000} שניות. נסה שוב בעוד רגע.`
    });
  }

  if (!AUTH_REQUIRED) return next();
  if (OPEN_PATHS.has(req.path)) return next();

  const authHeader = req.headers['x-bridge-token'] || req.headers['authorization'];
  const token = authHeader ? String(authHeader).replace(/^Bearer\s+/i, '').trim() : '';

  // השוואה בזמן קבוע כדי לא לאפשר גזירת הטוקן לפי זמני תגובה
  const a = Buffer.from(token);
  const b = Buffer.from(AUTH_TOKEN);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!ok) {
    return res.status(401).json({
      success: false,
      error: 'אימות נכשל. ודא שהערך בשדה "טוקן אימות הגשר" בתוסף תואם ל-BRIDGE_AUTH_TOKEN ב-.env.'
    });
  }

  const clientProtocol = Number(req.headers['x-gemmcp-protocol'] || 0);
  if (clientProtocol && clientProtocol !== PROTOCOL_VERSION) {
    return res.status(409).json({
      success: false,
      error: `אי התאמת גרסאות: התוסף מדבר פרוטוקול ${clientProtocol} והשרת ${PROTOCOL_VERSION}. עדכן את שניהם מאותו מקור.`
    });
  }

  next();
});

// ---------------------------------------------------------------------------
// סינון שאילתות SQL.
//
// במקור זו הייתה רשימת חסימה של תתי-מחרוזות. רשימת חסימה נכשלת בשני הכיוונים:
// היא חוסמת שאילתות תמימות שבמקרה מכילות מילה מהרשימה (למשל עמודה בשם
// user_grants), ומפספסת כל ניסוח שלא נמצא בה במדויק - הערות בתוך הפקודה,
// רווחים כפולים, או שרשור.
//
// כאן ההיפך: כברירת מחדל מותרות רק שאילתות קריאה. כתיבה דורשת הצהרה מפורשת
// ב-.env באמצעות SUPABASE_ALLOW_WRITES=true.
// ---------------------------------------------------------------------------
const SUPABASE_ALLOW_WRITES = process.env.SUPABASE_ALLOW_WRITES === 'true';

const READ_ONLY_STATEMENTS = ['SELECT', 'WITH', 'SHOW', 'EXPLAIN', 'TABLE', 'VALUES'];
const ALWAYS_BLOCKED = [
  /\bDROP\s+(DATABASE|SCHEMA|ROLE|USER)\b/i,
  /\bALTER\s+SYSTEM\b/i,
  /\b(GRANT|REVOKE)\b/i,
  /\b(CREATE|ALTER|DROP)\s+USER\b/i,
  /\bAUTH\.USERS\b/i,
  /\bPG_(SHADOW|AUTHID)\b/i
];

function sanitizeAndCheckQuery(query) {
  if (!query || typeof query !== 'string' || !query.trim()) {
    throw new Error('שאילתת SQL ריקה או לא תקינה');
  }

  // מסירים הערות כדי שלא ישמשו להסתרת פקודה
  const stripped = query
    .replace(/--[^\n]*/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .trim();

  for (const pattern of ALWAYS_BLOCKED) {
    if (pattern.test(stripped)) {
      throw new Error('פעולה חסומה מטעמי בטיחות: שינוי הרשאות או מחיקת סכימה אינם מורשים דרך הגשר.');
    }
  }

  const firstWord = (stripped.match(/^[A-Za-z]+/) || [''])[0].toUpperCase();
  const isReadOnly = READ_ONLY_STATEMENTS.includes(firstWord);

  if (!isReadOnly && !SUPABASE_ALLOW_WRITES) {
    throw new Error(
      `שאילתות כתיבה חסומות. הפקודה מתחילה ב-'${firstWord || '?'}'. ` +
      'כדי לאפשר כתיבה, הגדר SUPABASE_ALLOW_WRITES=true בקובץ .env.'
    );
  }

  // ריבוי פקודות בבקשה אחת מאפשר להסתיר פקודה שנייה אחרי פקודת קריאה
  const withoutStrings = stripped.replace(/'([^']|'')*'/g, "''");
  if (/;\s*\S/.test(withoutStrings)) {
    throw new Error('אין לשלוח יותר מפקודת SQL אחת בבקשה.');
  }

  return query;
}

// Endpoint לביצוע פקודות SQL ישירות
app.post('/api/execute', async (req, res) => {
  try {
    const { query, config } = req.body;
    const safeQuery = sanitizeAndCheckQuery(query);

    const supabaseUrl = config?.supabaseUrl || process.env.SUPABASE_URL;
    const supabaseKey = config?.supabaseKey || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY;

    if (!supabaseUrl || !supabaseKey) {
      return res.status(400).json({
        success: false,
        error: 'חסרים פרטי התחברות ל-Supabase (SUPABASE_URL או SUPABASE_KEY ב-.env או בהגדרות התוסף)'
      });
    }

    const supabase = createClient(supabaseUrl, supabaseKey);

    // ביצוע דרך RPC או שאילתת Postgres ישירה
    const { data, error } = await supabase.rpc('exec_sql', { query: safeQuery });

    if (error) {
      return res.status(400).json({
        success: false,
        error: error.message || 'שגיאה בהרצת SQL',
        hint: 'אם פונקציית exec_sql לא קיימת ב-Supabase שלך, הרץ את הסקריפט מ-setup_rpc.sql ב-SQL Editor של Supabase'
      });
    }

    res.json({
      success: true,
      data: data || []
    });
  } catch (err) {
    console.error('Execution error:', err.message);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Callback לקבלת אישור ה-OAuth מ-Supabase
app.get('/oauth/callback', (req, res) => {
  const { code, error } = req.query;

  if (error) {
    // בזרימת שגיאה אין פרמטר code, ולכן התוסף לא מחליף את הלשונית —
    // זהו המסך היחיד שהמשתמש רואה, בעיצוב תואם לדף האישור של התוסף.
    const safeError = String(error).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[c]);

    return res.send(`
      <!DOCTYPE html>
      <html lang="he" dir="rtl">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>שגיאת התחברות</title>
        <style>
          * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
          body {
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
            background: radial-gradient(120% 80% at 50% 0%, #1e293b 0%, #172033 45%, #0f172a 100%);
            background-color: #0f172a; color: #e2e8f0; padding: 20px;
          }
          .card {
            background: linear-gradient(160deg, #1e293b, #172033);
            border: 1px solid #334155; border-radius: 26px;
            padding: 42px 36px; max-width: 480px; width: 100%; text-align: center;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3), 0 20px 50px rgba(0, 0, 0, 0.45);
          }
          h1 { font-size: 25px; font-weight: 800; margin-bottom: 12px; letter-spacing: -0.2px; color: #f1f5f9; }
          p { font-size: 15px; color: #94a3b8; line-height: 1.55; }
          .badge {
            display: inline-flex; align-items: center; gap: 7px; margin-top: 24px;
            background: rgba(153, 27, 27, 0.25); color: #fca5a5; border: 1px solid rgba(220, 38, 38, 0.4);
            padding: 9px 20px; border-radius: 14px; font-size: 14px; font-weight: 700;
          }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>⚠️ ההתחברות בוטלה או נכשלה</h1>
          <p>${safeError}</p>
          <div class="badge">שגיאת אימות</div>
        </div>
      </body>
      </html>
    `);
  }

  // דף ביניים שקוף ויזואלית: התוסף מחליף מיד את הלשונית ב-oauth-success.html.
  // הרקע זהה לדף האישור הכהה של התוסף כדי שהמעבר לא יורגש כמסך נוסף.
  res.send(`
    <!DOCTYPE html>
    <html lang="he" dir="rtl">
    <head>
      <meta charset="UTF-8">
      <title>מתחבר...</title>
      <style>
        html, body { height: 100%; margin: 0; background: #0f172a; }
      </style>
    </head>
    <body></body>
    </html>
  `);
});

// מטמון זיכרון פנימי (RAM) לשמירת מפתחות ה-OAuth שנמשכו דינמית מה-DB (אם הוגדרו פרטי Supabase ב-.env)
let secretsCache = {};

async function fetchDynamicSecrets() {
  try {
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

    if (!supabaseUrl || !supabaseKey) return secretsCache;

    const supabase = createClient(supabaseUrl, supabaseKey);
    // ניסיון שליפה מטבלת gemmcp_settings או fallback ל-omnimcp_settings
    let { data, error } = await supabase.from('gemmcp_settings').select('*');
    if (error) {
      const fallback = await supabase.from('omnimcp_settings').select('*');
      if (!fallback.error) {
        data = fallback.data;
        error = null;
      }
    }

    if (!error && Array.isArray(data)) {
      data.forEach(row => {
        const sName = row.service_name;
        const secretKey = row.api_key;
        let cId = '';

        if (row.config && typeof row.config === 'object') {
          cId = row.config.client_id || row.config.clientId || '';
        } else if (typeof row.config === 'string') {
          try { 
            const parsed = JSON.parse(row.config);
            cId = parsed.client_id || parsed.clientId || ''; 
          } catch(e) {}
        }

        secretsCache[sName] = {
          clientId: cId,
          clientSecret: secretKey
        };
      });
      console.log('🔑 [Secrets Vault] מפתחות ה-OAuth נטענו בהצלחה דינמית מטבלת gemmcp_settings / omnimcp_settings:', Object.keys(secretsCache));
    } else if (error) {
      console.error('❌ [Secrets Vault] שגיאה בשליפת מפתחות מ-gemmcp_settings:', error.message);
    }
  } catch (err) {
    console.warn('⚠️ [Secrets Vault] לא ניתן היה למשוך מפתחות דינמיים מ-gemmcp_settings:', err.message);
  }
  return secretsCache;
}

// טעינה ראשונית בעת עליית השרת
fetchDynamicSecrets();

// נקודת קצה להחלפת OAuth code בטוקן
app.post('/api/oauth/exchange', async (req, res) => {
  try {
    const { service, code, redirectUri } = req.body;

    if (!code) {
      return res.status(400).json({ success: false, error: 'Missing code parameter' });
    }

    // רענון/ווידוא מפתחות מה-Vault במידת הצורך
    if (!secretsCache[service]) {
      await fetchDynamicSecrets();
    }

    const serviceVault = secretsCache[service] || {};

    if (service === 'notion') {
      const clientId = serviceVault.clientId || process.env.NOTION_CLIENT_ID;
      const clientSecret = serviceVault.clientSecret || process.env.NOTION_CLIENT_SECRET;
      
      if (!clientId || !clientSecret) {
        return res.status(500).json({
          success: false,
          error: 'מפתחות Notion OAuth לא נמצאו בשרת או בטבלת gemmcp_settings'
        });
      }

      const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
      const response = await fetch('https://api.notion.com/v1/oauth/token', {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${credentials}`,
          'Content-Type': 'application/json',
          'Notion-Version': '2022-06-28'
        },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: redirectUri || 'http://localhost:3000/oauth/callback'
        })
      });

      const data = await response.json();
      if (!response.ok) {
        return res.status(response.status).json({ success: false, error: data.error_description || data.error || data.message || 'Failed to exchange Notion code' });
      }

      return res.json({
        success: true,
        accessToken: data.access_token,
        workspaceName: data.workspace_name || 'Notion Workspace'
      });
    }

    if (service === 'github') {
      const clientId = serviceVault.clientId || process.env.GITHUB_CLIENT_ID;
      const clientSecret = serviceVault.clientSecret || process.env.GITHUB_CLIENT_SECRET;

      if (!clientId || !clientSecret) {
        return res.status(500).json({
          success: false,
          error: 'מפתחות GitHub OAuth לא נמצאו בשרת או בטבלת gemmcp_settings'
        });
      }

      const response = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code: code,
          redirect_uri: redirectUri || 'http://localhost:3000/oauth/callback'
        })
      });

      const data = await response.json();
      if (!response.ok || data.error) {
        return res.status(400).json({ success: false, error: data.error_description || data.error || 'Failed to exchange GitHub code' });
      }

      return res.json({
        success: true,
        accessToken: data.access_token
      });
    }

    if (service === 'supabase') {
      const clientId = serviceVault.clientId || process.env.SUPABASE_CLIENT_ID || 'f76e03ca-00e4-4c01-931e-10c4082315b1';
      const clientSecret = serviceVault.clientSecret || process.env.SUPABASE_CLIENT_SECRET;

      if (!clientSecret) {
        return res.status(500).json({
          success: false,
          error: 'מפתח SUPABASE_CLIENT_SECRET לא נמצא בטבלת gemmcp_settings'
        });
      }

      const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
      const response = await fetch('https://api.supabase.com/v1/oauth/token', {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${credentials}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri || 'http://localhost:3000/oauth/callback'
        })
      });

      const data = await response.json();
      if (!response.ok || data.error) {
        return res.status(400).json({ success: false, error: data.error_description || data.error || data.message || 'Failed to exchange Supabase code' });
      }

      return res.json({
        success: true,
        accessToken: data.access_token,
        refreshToken: data.refresh_token
      });
    }

    return res.status(400).json({ success: false, error: `Unsupported service: ${service}` });
  } catch (err) {
    console.error('[OAuth Exchange Error]:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- WINDOWS MCP ENDPOINTS & SERVER-SIDE SECURITY ---

// בדיקת בטיחות לפקודות שורת פקודה (PowerShell / CMD)
function checkDangerousWindowsCommands(cmd) {
  if (!cmd || typeof cmd !== 'string') return;
  const upper = cmd.toUpperCase();
  const blacklisted = [
    'FORMAT ',
    'DISKPART',
    'REG DELETE',
    'RD /S /Q C:',
    'RMDIR /S /Q C:',
    'DEL /F /S /Q C:\\WINDOWS',
    'REMOVE-ITEM -RECURSE -FORCE C:\\WINDOWS',
    ':(){ :|:& };:',
    'DROP DATABASE'
  ];
  for (const bl of blacklisted) {
    if (upper.includes(bl)) {
      throw new Error(`פעולה חסומה מטעמי בטיחות מערכת: שימוש בפקודה '${bl}' אסור.`);
    }
  }
}

// הרחבת נתיב משתמש: ~ (תיקיית הבית) ומשתני סביבה בסגנון %VAR% (למשל %USERPROFILE%)
// שולחן העבודה, המסמכים והתמונות מופנים ל-OneDrive במחשבים רבים, ואז
// os.homedir() + '/Desktop' הוא תיקייה כמעט ריקה שאינה מה שהמשתמש רואה.
//
// אומת מקצה לקצה: המודל ביקש '~/Desktop', הנתיב נפתר לתיקיית הבית, והבקשה
// נחסמה כחורגת מהתחום - למרות שהמשתמש התכוון בדיוק לתיקייה המורשית.
//
// הרישום הוא המקור הסמכותי: שם Windows רושם את ההפניה בפועל, ולכן לא מנחשים.
const KNOWN_FOLDER_KEYS = {
  desktop: 'Desktop',
  documents: 'Personal',
  pictures: 'My Pictures',
  music: 'My Music',
  videos: 'My Video',
  downloads: '{374DE290-123F-4565-9164-39C4925E467B}'
};

const knownFolders = (() => {
  const out = {};
  if (process.platform !== 'win32') return out;
  const SEP = String.fromCharCode(92);
  try {
    const regKey = ['HKCU', 'Software', 'Microsoft', 'Windows', 'CurrentVersion',
                    'Explorer', 'User Shell Folders'].join(SEP);
    // stdio מפורש. כשהשרת עולה דרך המשגר השקט הוא מנותק ובלי קונסולה, ואז
    // execFileSync שיורש handles נכשל - ה-catch בלע את זה, knownFolders נשאר
    // ריק, וכל בקשה ל-'~/Desktop' נחסמה. אומת: בחזית עבד, ברקע לא.
    const raw = require('child_process').execFileSync('reg', ['query', regKey],
      { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });

    for (const line of raw.split(String.fromCharCode(10))) {
      const t = line.trim();
      const marker = t.indexOf('REG_');
      if (marker <= 0) continue;
      const name = t.slice(0, marker).trim();
      const after = t.slice(marker);
      const sz = after.indexOf('SZ');
      if (sz === -1) continue;
      const value = after.slice(sz + 2).trim();

      const slot = Object.keys(KNOWN_FOLDER_KEYS)
        .find((k) => KNOWN_FOLDER_KEYS[k].toLowerCase() === name.toLowerCase());
      if (!slot || out[slot]) continue;

      const expanded = value.replace(/%([^%]+)%/g, (all, v) => process.env[v] || all);
      if (fs.existsSync(expanded)) out[slot] = expanded;
    }
  } catch (e) {
    console.warn('⚠️ קריאת תיקיות המערכת מהרישום נכשלה:', e.message);
  }

  // גיבוי כשהרישום לא נקרא: משתני הסביבה של OneDrive. פחות סמכותי מהרישום,
  // אבל הרבה יותר טוב מתיקיית הבית - שם התיקיות פשוט אינן קיימות במחשב מסונכרן.
  if (!out.desktop) {
    for (const base of [process.env.OneDrive, process.env.OneDriveCommercial, os.homedir()]) {
      if (!base) continue;
      for (const [slot, folder] of [['desktop', 'Desktop'], ['documents', 'Documents'],
                                    ['pictures', 'Pictures'], ['downloads', 'Downloads']]) {
        if (out[slot]) continue;
        const cand = path.join(base, folder);
        try { if (fs.existsSync(cand)) out[slot] = cand; } catch (e) { /* לא נגיש */ }
      }
    }
    if (out.desktop) console.warn('   נעשה שימוש בגיבוי: ' + out.desktop);
  }
  return out;
})();

function expandPath(inputPath) {
  if (!inputPath || typeof inputPath !== 'string') return inputPath;
  let p = inputPath.trim();

  // הרחבת ~ לתיקיית הבית של המשתמש (Windows: C:\Users\<user>)
  if (p === '~') {
    p = os.homedir();
  } else if (p.startsWith('~/') || p.startsWith('~\\')) {
    const rest = p.slice(2).split(String.fromCharCode(92)).join('/');
    const slash = rest.indexOf('/');
    const first = (slash === -1 ? rest : rest.slice(0, slash)).toLowerCase();
    const tail = slash === -1 ? '' : rest.slice(slash + 1);
    // '~/Desktop' חייב להצביע על שולחן העבודה שהמשתמש באמת רואה, גם כשהוא
    // מופנה ל-OneDrive. בלי זה כל בקשה של המודל ל-~/Desktop נחסמה כחריגה.
    p = knownFolders[first]
      ? (tail ? path.join(knownFolders[first], tail) : knownFolders[first])
      : path.join(os.homedir(), p.slice(2));
  }

  // הרחבת %VAR% מוגבלת לרשימת היתר של משתני נתיב מוכרים.
  // קודם הורחב כל משתנה סביבה, וב-process.env יושבים גם הסודות שנטענו מ-.env
  // דרך dotenv - כלומר נתיב שהמודל מייצר יכול היה לגרור ערך סודי לתוך המחרוזת.
  const SAFE_ENV_VARS = new Set([
    'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA',
    'TEMP', 'TMP', 'PUBLIC', 'PROGRAMDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)',
    'SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'ONEDRIVE'
  ]);
  p = p.replace(/%([^%]+)%/g, (match, name) => {
    const upper = String(name).toUpperCase();
    if (!SAFE_ENV_VARS.has(upper)) return match;   // לא מרחיבים - נשאר כטקסט
    const key = Object.keys(process.env).find(k => k.toUpperCase() === upper);
    return key ? process.env[key] : match;
  });

  return p;
}

// פתרון קישורים סימבוליים ו-junctions לפני בדיקת התחום. בלי זה, קיצור דרך
// שיושב בתוך התיקייה המותרת ומצביע החוצה מנהר את הגישה אל מחוץ לתחום.
function canonicalise(p) {
  const resolved = path.resolve(p);
  try {
    return fs.realpathSync.native(resolved);
  } catch (e) {
    // הנתיב עוד לא קיים. מטפסים כלפי מעלה עד לאב הקיים הקרוב ביותר, מפענחים
    // אותו מול הדיסק, ומחברים בחזרה את המקטעים החסרים.
    //
    // קודם נבדק רק ההורה המיידי, ולכן שני מקטעים חסרים או יותר גרמו לוויתור
    // מוחלט על הפענוח. אומת: junction בתוך התחום המותר, עם נתיב כמו
    // <מותר>/link/newdir/file.txt, עבר את בדיקת התחום וכתב מחוץ לתקרה.
    const missing = [];
    let cur = resolved;
    for (let i = 0; i < 64; i++) {
      const parent = path.dirname(cur);
      if (!parent || parent === cur) break;
      missing.unshift(path.basename(cur));
      cur = parent;
      try {
        return path.join(fs.realpathSync.native(cur), ...missing);
      } catch (e2) { /* ההורה גם אינו קיים - ממשיכים לטפס */ }
    }
    return resolved;
  }
}

// ---------------------------------------------------------------------------
// פענוח הרשאות.
//
// במקור ההרשאות שהגיעו בגוף הבקשה *דרסו* את הגדרות ה-.env, כך שהלקוח יכול היה
// להעניק לעצמו יותר ממה שהשרת התיר. אומת בפועל: בקשה עם allowedPath:"C:\" קראה
// את C:\Windows\System32 למרות ש-WIN_ALLOWED_PATH הוגבל לשולחן העבודה.
//
// כאן ה-.env הוא תקרה. הלקוח יכול רק לצמצם, לעולם לא להרחיב.
// ---------------------------------------------------------------------------
const SERVER_CEILING = {
  readFiles: process.env.WIN_PERM_READ !== 'false',
  writeFiles: process.env.WIN_PERM_WRITE === 'true',
  runCommands: process.env.WIN_PERM_COMMANDS === 'true',
  launchApps: process.env.WIN_PERM_APPS !== 'false',
  clipboard: process.env.WIN_PERM_CLIPBOARD !== 'false'
};

// נתיב ריק פירושו כעת "חסום", לא "כל הדיסק". פתיחת הדיסק כולו דורשת הצהרה
// מפורשת: WIN_ALLOWED_PATH=* .
const SERVER_ALLOWED_PATH = (() => {
  const raw = (process.env.WIN_ALLOWED_PATH || '').trim();
  if (raw === '*') return null;                       // ללא הגבלה, בבחירה מודעת
  if (raw) return path.resolve(expandPath(raw));

  // ברירת מחדל שמרנית: שולחן העבודה. ב-Windows עם OneDrive שולחן העבודה האמיתי
  // עשוי לשבת תחת OneDrive, ואז ~/Desktop הוא תיקייה כמעט ריקה שאינה מה שהמשתמש
  // רואה. בודקים את שניהם ובוחרים את זה שקיים ומאוכלס.
  const candidates = [];
  if (process.env.OneDrive) candidates.push(path.join(process.env.OneDrive, 'Desktop'));
  if (process.env.OneDriveCommercial) candidates.push(path.join(process.env.OneDriveCommercial, 'Desktop'));
  candidates.push(path.join(os.homedir(), 'Desktop'));

  for (const c of candidates) {
    try {
      if (fs.existsSync(c) && fs.readdirSync(c).length > 0) return c;
    } catch (e) { /* לא נגיש - ננסה את הבא */ }
  }
  return path.join(os.homedir(), 'Desktop');
})();

// השוואת נתיבים חייבת לכבד גבול של מפריד תיקיות. startsWith גולמי הופך תיקייה
// אחות בעלת אותה תחילית לחלק מהתחום המותר, ומאפשר לה לברוח ממנו.
function isPathInside(child, parent) {
  if (!parent) return true;                 // אין הגבלה
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

// תחום הקריאה נפרד מתחום הכתיבה.
//
// קודם נתיב אחד שלט בשניהם, ולכן כדי לקרוא קובץ מ-Downloads היה צריך לפתוח
// את Downloads גם למחיקה. זו החלפה גרועה: קריאה היא פעולה הפיכה ומחיקה אינה.
// ברירת המחדל כאן היא ללא הגבלת קריאה, והצמצום נעשה מההגדרות בתוסף.
const SERVER_READ_PATH = (() => {
  const raw = (process.env.WIN_READ_PATH || '*').trim();
  if (raw === '*') return null;                       // ללא הגבלה
  return path.resolve(expandPath(raw));
})();

// תיקיות מערכת חסומות תמיד, בכל היקף ובכל פעולה. "כל המחשב" פירושו כל מה
// ששייך למשתמש, לא קבצי מערכת. לקריאה מהן אין שימוש לגיטימי בכלי הזה, והן
// מכילות בדיוק את מה שכדאי שלא ידלוף.
const SYSTEM_PATHS = [
  process.env.SystemRoot,                 // C:\Windows
  process.env.ProgramFiles,
  process.env['ProgramFiles(x86)'],
  process.env.ProgramData,
  process.env.SystemDrive ? path.join(process.env.SystemDrive, '$Recycle.Bin') : null,

  // AppData ו-.ssh אינם תיקיות מערכת, אבל הם המקום שבו יושבים עוגיות, טוקנים,
  // פרופילי דפדפן ומפתחות פרטיים. "לקרוא את הקבצים שלי" לא מתכוון לאלה,
  // וחשיפתם למודל היא בדיוק מה שאסור שיקרה בטעות.
  // ההורה עצמו, ולא רק Roaming ו-Local: משתני הסביבה מצביעים על תתי-התיקיות,
  // ולכן בקשה ל-AppData עצמה עקפה את החסימה והציגה את שלושתן.
  path.join(os.homedir(), 'AppData'),
  process.env.APPDATA,
  process.env.LOCALAPPDATA,
  path.join(os.homedir(), '.ssh')
].filter(Boolean).map((p) => path.resolve(p));

function isSystemPath(target) {
  return SYSTEM_PATHS.some((sys) => {
    const rel = path.relative(sys, target);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  });
}

// היקפי קריאה שהתוסף יכול לבחור מהם. הלקוח שולח שם, לא נתיב, כדי שלא יוכל
// להמציא נתיב משלו - הוא בוחר מתוך רשימה שהשרת מגדיר.
function readScopeToPath(scope) {
  if (scope === 'everything') return null;
  if (scope === 'home') return os.homedir();
  if (scope === 'desktop') return SERVER_ALLOWED_PATH;
  return undefined;                                   // לא מוכר - מתעלמים
}

function resolvePermissions(clientPerms = {}) {
  // AND לוגי: הרשאה קיימת רק אם גם השרת וגם הלקוח מתירים אותה
  const narrow = (ceiling, requested) =>
    ceiling && (requested === undefined ? true : !!requested);

  let allowedPath = SERVER_ALLOWED_PATH;
  if (clientPerms.allowedPath) {
    const requested = path.resolve(expandPath(clientPerms.allowedPath));
    // מקבלים את בקשת הלקוח רק אם היא בתוך התקרה של השרת
    if (isPathInside(requested, allowedPath)) {
      allowedPath = requested;
    }
  }

  // הלקוח יכול רק לצמצם גם כאן. אם התקרה בשרת מגבילה, בחירה רחבה יותר
  // בתוסף לא תרחיב אותה.
  let readPath = SERVER_READ_PATH;
  const requestedRead = readScopeToPath(clientPerms.readScope);
  if (requestedRead !== undefined && requestedRead !== null) {
    if (isPathInside(requestedRead, SERVER_READ_PATH)) readPath = requestedRead;
  }

  return {
    readFiles: narrow(SERVER_CEILING.readFiles, clientPerms.readFiles),
    writeFiles: narrow(SERVER_CEILING.writeFiles, clientPerms.writeFiles),
    runCommands: narrow(SERVER_CEILING.runCommands, clientPerms.runCommands),
    launchApps: narrow(SERVER_CEILING.launchApps, clientPerms.launchApps),
    clipboard: narrow(SERVER_CEILING.clipboard, clientPerms.clipboard),
    allowedPath,
    readPath
  };
}

// ---------------------------------------------------------------------------
// יומן ביקורת מתמשך. ה-Activity Log שבדף חי בלשונית אחת ונמחק ברענון, ולכן לא
// נשאר שום תיעוד של מה בעצם הורץ על המחשב. כאן כל פעולה נרשמת לקובץ.
// ---------------------------------------------------------------------------
const AUDIT_FILE = path.join(__dirname, 'audit.log');
const AUDIT_MAX_BYTES = Number(process.env.WIN_AUDIT_MAX_BYTES) || 5 * 1024 * 1024;

// היומן נכתב לכל פעולה ולא נמחק לעולם, כך שהוא גדל בלי גבול. שומרים דור אחד
// אחורה: מי שבודק אירוע צריך את ההיסטוריה הקרובה, לא את כל חיי ההתקנה.
function rotateAuditIfNeeded() {
  try {
    if (fs.statSync(AUDIT_FILE).size < AUDIT_MAX_BYTES) return;
    fs.renameSync(AUDIT_FILE, AUDIT_FILE + '.1');
  } catch (e) { /* אין קובץ עדיין, או שהסיבוב נכשל - לא מפילים בגלל יומן */ }
}

function auditLog(action, params, outcome, detail) {
  rotateAuditIfNeeded();
  // לא כותבים תוכן קבצים או טקסט לוח שלם - רק מה שצריך כדי לשחזר מה קרה
  const safeParams = {};
  for (const [k, v] of Object.entries(params || {})) {
    if (typeof v === 'string' && v.length > 200) {
      safeParams[k] = `${v.slice(0, 200)}… (${v.length} chars)`;
    } else {
      safeParams[k] = v;
    }
  }
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    action,
    params: safeParams,
    outcome,
    detail: detail ? String(detail).slice(0, 300) : undefined
  });
  fs.appendFile(AUDIT_FILE, line + '\n', (err) => {
    if (err) console.warn('⚠️ כתיבה ליומן הביקורת נכשלה:', err.message);
  });
}

// Endpoint מרכזי לביצוע פעולות Windows MCP
// מקור אחד לתלויות של ה-handler. שתי נקודות הקריאה חייבות להעביר בדיוק את
// אותו אובייקט: כשהחתימה עברה לשלושה פרמטרים עודכנה רק נקודת הקריאה של
// /execute, ומסלול התוכניות נשאר על החתימה הישנה - כך שכל תוכנית נפלה על
// "Cannot destructure property 'resolvePermissions' of 'deps'".
const windowsDeps = {
  resolvePermissions, auditLog, canonicalise, expandPath, isPathInside, isSystemPath, checkDangerousWindowsCommands
};

app.post('/api/windows/execute', (req, res) => handleWindowsExecute(req, res, windowsDeps));

// ---------------------------------------------------------------------------
// הרצת תוכנית: רצף פעולות עם העברת ערכים ביניהן.
//
// כל שלב מבוצע דרך אותו handler של הפעולה הבודדת, עם res מדומה שקולט את
// התשובה. כך ההרשאות, בדיקת הנתיב ויומן הביקורת חלים על כל שלב בדיוק כמו על
// פקודה רגילה, בלי מסלול מקביל שיכול להתפצל מהמקורי.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// הרצת פקודה עם פלט חי (SSE).
//
// run_command הרגיל מחזיר הכל בסוף, אחרי עד 30 שניות של שקט מוחלט. לפעולה
// ארוכה זה נראה כמו תקיעה, ואין שום דרך לדעת אם משהו קורה. כאן הפלט משודר
// שורה-שורה בזמן אמת, והטיימאאוט ארוך יותר כי יש חיווי.
// ---------------------------------------------------------------------------
app.post('/api/windows/stream', (req, res) => {
  const { command, permissions = {} } = req.body || {};
  const perms = resolvePermissions(permissions);

  if (!perms.runCommands) {
    return res.status(403).json({ success: false, error: 'הרשאת הרצת פקודות מערכת כבויה בהגדרות התוסף או השרת.' });
  }
  if (!command) {
    return res.status(400).json({ success: false, error: 'חסר פרמטר command' });
  }
  try {
    checkDangerousWindowsCommands(command);
  } catch (e) {
    return res.status(400).json({ success: false, error: e.message });
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  const send = (event, data) => res.write(`event: ${event}
data: ${JSON.stringify(data)}

`);

  const child = execFile('powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command],
    { cwd: perms.allowedPath || process.cwd(), timeout: 120000, maxBuffer: 1024 * 1024 * 10 });

  let outBytes = 0;
  child.stdout.on('data', (chunk) => { outBytes += chunk.length; send('stdout', { chunk: String(chunk) }); });
  child.stderr.on('data', (chunk) => { send('stderr', { chunk: String(chunk) }); });

  child.on('error', (err) => {
    auditLog('run_command_stream', { command }, 'denied', err.message);
    send('error', { error: err.message });
    res.end();
  });

  child.on('close', (code, signal) => {
    auditLog('run_command_stream', { command }, code === 0 ? 'success' : 'failed', 'exit ' + code);
    send('done', { exitCode: code, signal: signal || null, bytes: outBytes });
    res.end();
  });

  // אם הלקוח מתנתק, אין טעם להשאיר תהליך רץ
  req.on('close', () => { try { child.kill(); } catch (e) {} });
});

// ביטול התקנה: עוצר את המתקין אם הוא עוד רץ, ומוחק את מה שהורד.
// זה מה שהופך התקנה מפעולה בלתי הפיכה למשהו שאפשר לחזור ממנו.
app.post('/api/windows/install/cancel', (req, res) => {
  const { jobId } = req.body || {};
  const out = cancelInstallJob(jobId);
  auditLog('install_cancel', { jobId }, out.found ? 'success' : 'denied',
           out.found ? `נמחקו ${out.removed.length} פריטים` : 'משימה לא נמצאה');
  if (!out.found) {
    return res.status(404).json({ success: false, error: 'לא נמצאה משימת התקנה עם המזהה הזה.' });
  }
  return res.json({ success: true, data: out });
});

app.get('/api/windows/install/jobs', (req, res) => {
  res.json({ success: true, data: listInstallJobs() });
});

app.post('/api/windows/plan', async (req, res) => {
  const { plan, permissions = {} } = req.body || {};

  async function runAction(action, params) {
    return new Promise((resolve, reject) => {
      let statusCode = 200;
      const fakeRes = {
        status(code) { statusCode = code; return this; },
        json(body) {
          if (statusCode >= 400 || !body || body.success === false) {
            const e = new Error((body && body.error) || `שגיאה (${statusCode})`);
            e.status = statusCode >= 400 ? statusCode : 500;
            return reject(e);
          }
          resolve(body.data);
        }
      };
      Promise.resolve(handleWindowsExecute({ body: { action, params, permissions } }, fakeRes, windowsDeps))
        .catch(reject);
    });
  }

  try {
    const result = await runPlan(plan, runAction);
    auditLog('plan', { steps: plan.length }, 'success');
    return res.json({ success: true, data: result });
  } catch (err) {
    auditLog('plan', { steps: Array.isArray(plan) ? plan.length : 0 }, 'denied', err.message);
    return res.status(err.status || 500).json({
      success: false,
      error: err.message,
      partial: err.partial || null
    });
  }
});

// בדיקת תקינות שרת
app.get('/api/health', (req, res) => {
  // נתיב פתוח בכוונה, ולכן אינו חושף את הטוקן עצמו - רק את מה שהתוסף צריך
  // כדי להציג מצב נכון ולהנחות את המשתמש.
  const authHeader = req.headers['x-bridge-token'] || req.headers['authorization'];
  const token = authHeader ? String(authHeader).replace(/^Bearer\s+/i, '').trim() : '';
  let authenticated = false;
  if (token) {
    const a = Buffer.from(token);
    const b = Buffer.from(AUTH_TOKEN);
    authenticated = a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  res.json({
    status: 'ok',
    bridge: 'GemMCP-Gemini-Bridge',
    platform: process.platform,
    protocol: PROTOCOL_VERSION,
    // אילו תיקיות מערכת נפתרו בפועל. כשהפענוח נכשל בשקט, כל בקשה ל-'~/Desktop'
    // נחסמה ולא היה שום סימן למה - עכשיו זה נראה מיד מ-/api/health.
    knownFolders,
    authRequired: AUTH_REQUIRED,
    authenticated: AUTH_REQUIRED ? authenticated : true,
    permissions: {
      readFiles: SERVER_CEILING.readFiles,
      writeFiles: SERVER_CEILING.writeFiles,
      runCommands: SERVER_CEILING.runCommands,
      launchApps: SERVER_CEILING.launchApps,
      clipboard: SERVER_CEILING.clipboard,
      allowedPath: SERVER_ALLOWED_PATH || '*'
    },
    supabaseWrites: SUPABASE_ALLOW_WRITES
  });
});

// עדכון אוטומטי של התוסף ושרת ה-Bridge ישירות מ-GitHub
// ---------------------------------------------------------------------------
// /api/update הוסר בכוונה.
//
// בגרסה 2.1.2 הוא היה endpoint ללא שום אימות שמריץ git pull או מוריד ZIP
// מ-GitHub ומחליף את הקוד המקומי דרך PowerShell. מכיוון שה-CORS מאשר גם
// בקשות ללא origin, כל תהליך מקומי שמגיע ל-localhost:3000 היה יכול לגרום
// למחשב להוריד ולהריץ קוד חדש. עדכון גרסה נעשה ידנית.
// ---------------------------------------------------------------------------

// כיבוי שרת ה-Bridge לפי בקשת המשתמש
app.post('/api/shutdown', (req, res) => {
  res.json({ success: true, message: 'שרת ה-Bridge נסגר בהצלחה.' });
  console.log('🛑 התקבלה בקשת כיבוי שרת מהתוסף - סוגר תהליך...');
  try {
    if (typeof server !== 'undefined' && server.close) {
      server.close();
    }
  } catch (e) {}
  setTimeout(() => {
    process.exit(0);
  }, 100);
});

// הפעלת השרת

// מטפל שגיאות אחרון. בלעדיו שגיאת CORS או JSON פגום נופלות למטפל ברירת המחדל
// של Express, שמחזיר דף HTML עם stack trace ובו נתיב ההתקנה ושם המשתמש - לפני
// כל אימות.
app.use((err, req, res, next) => {
  const isJsonParse = err && err.type === 'entity.parse.failed';
  const status = isJsonParse ? 400 : (err && err.status) || 500;
  console.warn('⚠️ בקשה נדחתה:', err && err.message);
  res.status(status).json({
    success: false,
    error: isJsonParse ? 'גוף הבקשה אינו JSON תקין.' : 'הבקשה נדחתה.'
  });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`\n==================================================`);
  console.log(`🚀 Windows Bridge Server רץ ומאזין בכתובת: http://${HOST}:${PORT}`);
  console.log(`🔒 נעול לגישה מקומית בלבד (Localhost / Extensions)`);
  console.log(`   פרוטוקול: ${PROTOCOL_VERSION}`);
  console.log(`--------------------------------------------------`);
  console.log(`🔑 אימות טוקן : ${AUTH_REQUIRED ? 'נאכף' : 'כבוי (הגדר BRIDGE_AUTH_TOKEN ב-.env כדי להפעיל)'}`);
  console.log(`--------------------------------------------------`);
  console.log(`הרשאות פעילות בשרת:`);
  console.log(`   קריאת קבצים   : ${SERVER_CEILING.readFiles ? 'כן' : 'לא'}`);
  console.log(`   כתיבת קבצים   : ${SERVER_CEILING.writeFiles ? 'כן' : 'לא'}`);
  console.log(`   הרצת פקודות   : ${SERVER_CEILING.runCommands ? 'כן' : 'לא'}`);
  console.log(`   פתיחת תוכנות  : ${SERVER_CEILING.launchApps ? 'כן' : 'לא'}`);
  console.log(`   לוח העתקה     : ${SERVER_CEILING.clipboard ? 'כן' : 'לא'}`);
  console.log(`   נתיב מותר     : ${SERVER_ALLOWED_PATH || 'כל הדיסק (WIN_ALLOWED_PATH=*)'}`);
  console.log(`   כתיבה ל-SQL   : ${SUPABASE_ALLOW_WRITES ? 'כן' : 'לא'}`);
  console.log(`   יומן ביקורת   : ${AUDIT_FILE}`);
  console.log(`==================================================\n`);
});

