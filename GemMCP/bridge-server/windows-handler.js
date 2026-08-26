const fs = require('fs');
const os = require('os');
const path = require('path');
const { exec, execFile } = require('child_process');
const { createFileActions } = require('./actions-files');

async function handleWindowsExecute(req, res, deps) {
  const { resolvePermissions, auditLog, canonicalise, expandPath, isPathInside, checkDangerousWindowsCommands } = deps;
  try {
    const { action, params = {}, permissions = {} } = req.body;
    const perms = resolvePermissions(permissions);

    // עוטפים את res כדי שכל תשובה תירשם ביומן בלי לפזר קריאות auditLog
    const originalJson = res.json.bind(res);
    let logged = false;
    res.json = (body) => {
      if (!logged) {
        logged = true;
        auditLog(action, params, body && body.success ? 'success' : 'denied', body && body.error);
      }
      return originalJson(body);
    };

    // בדיקת נתיב מותר (Allowed Directory Scope)
    function validatePathInScope(targetPath) {
      if (!targetPath) return;
      const resolved = canonicalise(path.resolve(expandPath(targetPath)));
      const ceiling = perms.allowedPath ? canonicalise(perms.allowedPath) : null;
      if (ceiling && !isPathInside(resolved, ceiling)) {
        throw new Error(`הגישה לנתיב '${targetPath}' נחסמה. הנתיב המורשה בהגדרות השרת הוא: ${perms.allowedPath}`);
      }
      return resolved;
    }

    switch (action) {
      // 1. קריאת קובץ
      
      case 'media_control': {
        // שליטה במדיה מריצה PowerShell. קודם לא הייתה כאן שום בדיקת הרשאה -
        // כלומר הפעולה רצה גם כשכל ההרשאות כבויות. אומת בהרצה.
        if (!perms.launchApps) {
          return res.status(403).json({ success: false, error: 'הרשאת שליטה בתוכנות (WIN_PERM_APPS) כבויה בשרת.' });
        }
        const cmd = params.command;
        let psCode = '';
        if (cmd === 'mute') psCode = '$obj = new-object -com wscript.shell; $obj.SendKeys([char]173)';
        else if (cmd === 'vol_down') psCode = '$obj = new-object -com wscript.shell; $obj.SendKeys([char]174)';
        else if (cmd === 'vol_up') psCode = '$obj = new-object -com wscript.shell; $obj.SendKeys([char]175)';
        else if (cmd === 'next') psCode = '$obj = new-object -com wscript.shell; $obj.SendKeys([char]176)';
        else if (cmd === 'prev') psCode = '$obj = new-object -com wscript.shell; $obj.SendKeys([char]177)';
        else if (cmd === 'play_pause') psCode = '$obj = new-object -com wscript.shell; $obj.SendKeys([char]179)';
        
        if (!psCode) return res.status(400).json({ success: false, error: 'Unknown media command' });
        
        return new Promise((resolve) => {
          execFile('powershell.exe',
            ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', psCode],
            { timeout: 10000, windowsHide: true }, (error) => {
            if (error) resolve(res.json({ success: false, error: error.message }));
            else resolve(res.json({ success: true, data: { message: 'פקודת המדיה נשלחה בהצלחה.' } }));
          });
        });
      }
      
      case 'manage_windows': {
        // אותו פער: הרצת PowerShell בלי בדיקת הרשאה. 'list' גם מונה את כל
        // החלונות הפתוחים על שמותיהם, שזו חשיפת מידע על מה שהמשתמש עושה.
        if (!perms.launchApps) {
          return res.status(403).json({ success: false, error: 'הרשאת שליטה בתוכנות (WIN_PERM_APPS) כבויה בשרת.' });
        }
        const cmd = params.command;
        const appName = params.app_name;
        
        if (cmd === 'list') {
          const psCode = `Get-Process | Where-Object { $_.MainWindowTitle -and $_.MainWindowTitle.Trim().Length -gt 0 } | Select-Object -Property Id, ProcessName, MainWindowTitle | ConvertTo-Json`;
          return new Promise((resolve) => {
            execFile('powershell.exe',
              ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', psCode],
              { timeout: 15000, windowsHide: true }, (error, stdout) => {
              if (error) {
                resolve(res.json({ success: false, error: error.message }));
              } else {
                try {
                  const parsed = JSON.parse(stdout || '[]');
                  const list = Array.isArray(parsed) ? parsed : [parsed];
                  resolve(res.json({ success: true, data: { open_windows: list } }));
                } catch (e) {
                  // stdout עשוי להיות undefined כשהפקודה לא הדפיסה דבר, ואז
                  // .trim() היה זורק בתוך ה-catch ומשאיר את הבקשה תלויה.
                  resolve(res.json({ success: true, data: { raw_output: String(stdout || '').trim() } }));
                }
              }
            });
          });
        
        
        
        
        
        } else if (cmd === 'focus' && appName) {
          const psCode = `
$target = [regex]::Escape($env:GEMMCP_TARGET)
$proc = Get-Process | Where-Object { 
    ($_.MainWindowTitle -and $_.MainWindowTitle -match $target) -or
    ($_.ProcessName -and $_.ProcessName -match $target)
} | Select-Object -First 1

if (-not $proc) {
    Write-Error "No window found matching the requested name."
    exit 1
}

$wshell = New-Object -ComObject WScript.Shell

# 1. Activate window by PID or Title
$activated = $wshell.AppActivate($proc.Id)
if (-not $activated -and $proc.MainWindowTitle) {
    $activated = $wshell.AppActivate($proc.MainWindowTitle)
}

# 2. Restore if minimized (Alt + Space, R)
Start-Sleep -Milliseconds 50
$wshell.SendKeys('% r')

# 3. Final focus
Start-Sleep -Milliseconds 50
$wshell.AppActivate($proc.Id)

Write-Output "Focused."
`;
          return new Promise((resolve) => {
            execFile('powershell.exe',
              ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', psCode],
              { timeout: 15000, windowsHide: true, env: { ...process.env, GEMMCP_TARGET: String(appName) } },
              (error, stdout, stderr) => {
              if (error || (stderr && stderr.includes('Error'))) {
                // לא מחזירים את stderr הגולמי: הוא כלל את קוד ה-PowerShell שנוצר,
                // כולל מה שנשלח כפרמטר. הפירוט נשאר בצד השרת.
                console.warn('[manage_windows focus]', stderr || (error && error.message));
                resolve(res.json({ success: false, error: `לא נמצא חלון פעיל שתואם ל-'${appName}'.` }));
              } else {
                resolve(res.json({ success: true, data: { message: `חלון ${appName} הוקפץ בהצלחה לקדמת המסך!` } }));
              }
            });
          });

        }
        return res.status(400).json({ success: false, error: 'Unknown manage_windows command' });
      }

      case 'read_file': {
        if (!perms.readFiles) {
          return res.status(403).json({ success: false, error: 'הרשאת קריאת קבצים (WIN_PERM_READ) כבויה בשרת.' });
        }
        if (!params.path) {
          return res.status(400).json({ success: false, error: 'חסר פרמטר path של הקובץ לקריאה' });
        }
        const filePath = validatePathInScope(params.path);
        if (!fs.existsSync(filePath)) {
          return res.status(404).json({ success: false, error: `הקובץ אינו קיים: ${params.path}` });
        }
        const content = fs.readFileSync(filePath, 'utf8');

        // חלון קריאה נשלט במקום חיתוך קבוע ב-50k. קובץ גדול נקרא בקטעים
        // רצופים במקום להיחתך בשקט באמצע.
        const rfOffset = Math.max(0, Number(params.offset) || 0);
        const rfLimit = Math.min(Math.max(1, Number(params.limit) || 50000), 200000);
        const slice = content.slice(rfOffset, rfOffset + rfLimit);

        return res.json({
          success: true,
          data: {
            path: params.path,
            totalChars: content.length,
            offset: rfOffset,
            returned: slice.length,
            hasMore: rfOffset + slice.length < content.length,
            content: slice
          }
        });
      }

      // 2. רשימת קבצים בתיקייה
      case 'list_directory': {
        if (!perms.readFiles) {
          return res.status(403).json({ success: false, error: 'הרשאת קריאת קבצים ותיקיות (WIN_PERM_READ) כבויה בשרת.' });
        }
        const dirPath = validatePathInScope(params.path || perms.allowedPath || process.cwd());
        if (!fs.existsSync(dirPath)) {
          return res.status(404).json({ success: false, error: `התיקייה אינה קיימת: ${params.path}` });
        }
        const all = fs.readdirSync(dirPath, { withFileTypes: true }).map(item => ({
          name: item.name,
          type: item.isDirectory() ? 'directory' : 'file',
          path: path.join(dirPath, item.name)
        }));

        // עימוד במקום חיתוך שקט. קודם הוחזרו 100 פריטים בלי שום סימן שיש עוד,
        // כך שהמודל עבד על תמונה חלקית בלי לדעת את זה.
        const lsOffset = Math.max(0, Number(params.offset) || 0);
        const lsLimit = Math.min(Math.max(1, Number(params.limit) || 200), 1000);
        const lsPage = all.slice(lsOffset, lsOffset + lsLimit);

        return res.json({
          success: true,
          data: {
            directory: dirPath,
            total: all.length,
            offset: lsOffset,
            limit: lsLimit,
            returned: lsPage.length,
            hasMore: lsOffset + lsPage.length < all.length,
            items: lsPage
          }
        });
      }

      // 3. כתיבה או יצירת קובץ
      case 'write_file': {
        if (!perms.writeFiles) {
          return res.status(403).json({ success: false, error: 'הרשאת כתיבת ועריכת קבצים כבויה בהגדרות התוסף או השרת.' });
        }
        if (!params.path || typeof params.content !== 'string') {
          return res.status(400).json({ success: false, error: 'חסרים פרמטרי path או content לכתיבה' });
        }
        const filePath = validatePathInScope(params.path);
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(filePath, params.content, 'utf8');
        return res.json({ success: true, data: { message: `הקובץ נשמר בהצלחה בנתיב: ${filePath}`, bytes: Buffer.byteLength(params.content, 'utf8') } });
      }

      // 4. הרצת פקודת PowerShell / CMD
      case 'run_command': {
        if (!perms.runCommands) {
          return res.status(403).json({ success: false, error: 'הרשאת הרצת פקודות מערכת כבויה בהגדרות התוסף או השרת.' });
        }
        if (!params.command) {
          return res.status(400).json({ success: false, error: 'חסר פרמטר command להרצה' });
        }
        checkDangerousWindowsCommands(params.command);

        const cwd = perms.allowedPath || process.cwd();
        // execFile ולא exec: Node לא פותח shell שמפרסר את המחרוזת בעצמו.
        // -NoProfile קריטי - בלעדיו PowerShell טוען את הפרופיל של המשתמש לפני
        // כל פקודה, כך שכל מי שיכול לכתוב לקובץ הפרופיל מריץ קוד בכל קריאה.
        execFile('powershell.exe',
          ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', params.command],
          { cwd, timeout: 30000, maxBuffer: 1024 * 1024 * 5 }, (error, stdout, stderr) => {
          if (error) {
            return res.json({
              success: false,
              error: error.message,
              stderr: stderr ? stderr.toString() : null,
              stdout: stdout ? stdout.toString() : null
            });
          }
          return res.json({
            success: true,
            data: {
              stdout: (stdout || '').toString().slice(0, 30000),
              stderr: (stderr || '').toString().slice(0, 10000),
              cwd: cwd
            }
          });
        });
        return;
      }

      // 5. פתיחת אפליקציה
      case 'open_app': {
        if (!perms.launchApps) {
          return res.status(403).json({ success: false, error: 'הרשאת הפעלת תוכנות (WIN_PERM_APPS) כבויה בשרת.' });
        }
        if (!params.app_name && !params.path) {
          return res.status(400).json({ success: false, error: 'חסר שם אפליקציה או נתיב להרצה (app_name)' });
        }
        
        let appTarget = (params.path || params.app_name || '').trim();
        const appLow = appTarget.toLowerCase().replace(/['"״]/g, '');

        const appAliases = {
          // AI & Chat
          'claude': 'claude',
          'קלוד': 'claude',
          'chatgpt': 'chatgpt',
          'gpt': 'chatgpt',
          'גפט': 'chatgpt',
          // Productivity & Code
          'vscode': 'code',
          'code': 'code',
          'קוד': 'code',
          'cursor': 'cursor',
          'קראוסר': 'cursor',
          'visual studio': 'devenv',
          'notepad': 'notepad',
          'פנקס רשימות': 'notepad',
          'word': 'winword',
          'וורד': 'winword',
          'winword': 'winword',
          'excel': 'excel',
          'אקסל': 'excel',
          'powerpoint': 'powerpnt',
          'פאוורפוינט': 'powerpnt',
          'notion': 'notion:',
          'נושן': 'notion:',
          'figma': 'figma:',
          'פיגמה': 'figma:',
          // Communication
          'whatsapp': 'whatsapp:',
          'ווטסאפ': 'whatsapp:',
          'וואטסאפ': 'whatsapp:',
          'telegram': 'telegram:',
          'טלגרם': 'telegram:',
          'discord': 'discord:',
          'דיסקורד': 'discord:',
          'slack': 'slack:',
          'סלאק': 'slack:',
          'teams': 'msteams:',
          'טימס': 'msteams:',
          // Media & Utilities
          'spotify': 'spotify:',
          'ספוטיפיי': 'spotify:',
          'calc': 'calculator:',
          'calculator': 'calculator:',
          'מחשבון': 'calculator:',
          'paint': 'mspaint',
          'צייר': 'mspaint',
          'camera': 'microsoft.windows.camera:',
          'מצלמה': 'microsoft.windows.camera:',
          'explorer': 'explorer',
          'סייר הקבצים': 'explorer',
          'settings': 'ms-settings:',
          'הגדרות': 'ms-settings:',
          'clock': 'ms-clock:',
          'שעון': 'ms-clock:',
          'store': 'ms-windows-store:',
          'חנות': 'ms-windows-store:',
          'taskmgr': 'taskmgr',
          'מנהל המשימות': 'taskmgr',
          'cmd': 'cmd',
          'powershell': 'powershell',
          'terminal': 'wt',
          'טרמינל': 'wt',
          // Browsers
          'chrome': 'chrome',
          'כרום': 'chrome',
          'edge': 'msedge',
          'אדג': 'msedge',
          'brave': 'brave',
          'firefox': 'firefox'
        };

        let targetToRun = appAliases[appLow] || appTarget;

        // הרצה ישירה דרך cmd /c start המקפיצה מיד כל פרוטוקול/תוכנה בשולחן העבודה
        const targetCommand = targetToRun.includes(':') 
          ? `start "" "${targetToRun}"` 
          : `start "" ${targetToRun}`;

        // start מחזירה תמיד קוד יציאה 0, ולכן היא אינה עדות לכך שמשהו באמת נפתח.
        // גרוע מכך - יעד שאינו קיים תוקע את cmd בהמתנה לדיאלוג שגיאה, והבקשה
        // לעולם לא חוזרת בעוד תהליך cmd נשאר תלוי. לכן בודקים מראש שהיעד קיים,
        // ומגבילים כל הרצה בזמן כרשת ביטחון.
        const LAUNCH_TIMEOUT_MS = 5000;

        const reportLaunched = () =>
          res.json({ success: true, data: { message: `היישום '${appTarget}' הופעל בהצלחה ב-Windows!` } });

        // היעד מגיע בסופו של דבר מפלט של מודל, ולכן חייב לעבור אימות תווים לפני
        // שהוא נוגע ב-cmd. תו כמו & או | היה הופך פתיחת תוכנה להרצת פקודה שרירותית.
        const SAFE_EXE = /^[A-Za-z0-9._-]+$/;
        const SAFE_URI = /^[A-Za-z][A-Za-z0-9.+-]*:[^"'`|&;<>^%\r\n]*$/;
        if (!SAFE_EXE.test(targetToRun) && !SAFE_URI.test(targetToRun)) {
          return res.status(400).json({
            success: false,
            error: `שם היישום '${appTarget}' מכיל תווים שאינם מורשים.`
          });
        }

        const launchTarget = () => {
          // execFile ולא exec - הארגומנטים מועברים כמערך ואינם עוברים פירוש shell
          execFile('cmd.exe', ['/c', 'start', '', targetToRun],
            { windowsHide: false, timeout: LAUNCH_TIMEOUT_MS, killSignal: 'SIGKILL' }, (cmdErr) => {
            if (!cmdErr) {
              return reportLaunched();
            }

            if (cmdErr.killed) {
              return res.status(504).json({
                success: false,
                error: `פתיחת '${appTarget}' לא הסתיימה בזמן ובוטלה. ייתכן שממתין לך דיאלוג על המסך.`
              });
            }

            // Fallback ל-PowerShell במידה ו-cmd start נכשל
            execFile('powershell.exe',
              ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', `Start-Process "${targetToRun}"`],
              { timeout: LAUNCH_TIMEOUT_MS, killSignal: 'SIGKILL' },
              (psErr) => {
                if (psErr) {
                  const reason = psErr.killed ? 'היעד לא הגיב בזמן' : psErr.message;
                  return res.status(500).json({ success: false, error: `שגיאה בפתיחת ${appTarget}: ${reason}` });
                }
                return reportLaunched();
              });
          });
        };

        if (targetToRun.includes(':')) {
          // פרוטוקול: קיים רק אם ה-scheme רשום ב-Registry
          const scheme = targetToRun.split(':')[0];
          execFile('reg.exe', ['query', `HKCR\\${scheme}`, '/ve'], { timeout: LAUNCH_TIMEOUT_MS }, (regErr) => {
            if (regErr) {
              return res.status(404).json({
                success: false,
                error: `היישום '${appTarget}' אינו מותקן במחשב (הפרוטוקול '${scheme}:' אינו רשום).`
              });
            }
            launchTarget();
          });
        } else {
          // קובץ הרצה: קיים רק אם where.exe מוצא אותו ב-PATH
          execFile('where.exe', [targetToRun], { timeout: LAUNCH_TIMEOUT_MS }, (whereErr) => {
            if (whereErr) {
              return res.status(404).json({
                success: false,
                error: `היישום '${appTarget}' לא נמצא במחשב ('${targetToRun}' אינו קיים ב-PATH).`
              });
            }
            launchTarget();
          });
        }
        return;
      }

      // 6. פעולות קבצים נוספות: העתקה, העברה, מחיקה לסל, יצירת תיקייה, חיפוש
      case 'make_dir':
      case 'copy_file':
      case 'move_file':
      case 'delete_file':
      case 'find_files': {
        const fileActions = createFileActions({ validatePathInScope, perms });
        try {
          const data = await fileActions[action](params);
          return res.json({ success: true, data });
        } catch (e) {
          return res.status(e.status || 500).json({ success: false, error: e.message });
        }
      }

      // 7. קריאה או כתיבה ללוח (Clipboard)
      case 'clipboard_read': {
        if (!perms.clipboard) {
          return res.status(403).json({ success: false, error: 'הרשאת גישה ללוח (WIN_PERM_CLIPBOARD) כבויה בשרת.' });
        }
        execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Get-Clipboard'], (error, stdout) => {
          if (error) {
            return res.status(500).json({ success: false, error: error.message });
          }
          return res.json({ success: true, data: { clipboard_content: (stdout || '').trim() } });
        });
        return;
      }

      case 'clipboard_write': {
        if (!perms.clipboard) {
          return res.status(403).json({ success: false, error: 'הרשאת גישה ללוח (WIN_PERM_CLIPBOARD) כבויה בשרת.' });
        }
        const textToCopy = params.text || '';
        const child = execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '$input | Set-Clipboard'], (error) => {
          if (error) {
            return res.status(500).json({ success: false, error: error.message });
          }
          return res.json({ success: true, data: { message: 'הטקסט הועתק ללוח של Windows בהצלחה!' } });
        });
        if (child.stdin) {
          child.stdin.end(textToCopy, 'utf8');
        }
        return;
      }

      default:
        return res.status(400).json({
          success: false,
          error: `פעולה לא מוכרת ב-Windows MCP: '${action}'. פעולות אפשריות: read_file, write_file, list_directory, run_command, open_app, clipboard_read, clipboard_write.`
        });
    }
  } catch (err) {
    console.error('[Windows MCP Error]:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
}

module.exports = { handleWindowsExecute };
