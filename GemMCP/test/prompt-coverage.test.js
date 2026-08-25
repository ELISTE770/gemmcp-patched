/**
 * בדיקה שהפרומפט מפרסם את כל מה שהשרת באמת יודע לעשות.
 *   node test/prompt-coverage.test.js
 *
 * למה זה קיים: רשימת הפעולות בפרומפט היא כל מה שהמודל יודע עליו. היא פרסמה
 * run_command אבל השמיטה את make_dir, copy_file, move_file, delete_file
 * ו-find_files - ואומת בפועל שכשהתבקש ליצור תיקייה, ג'מיני פלט
 * run_command עם New-Item, כי PowerShell היה הכלי היחיד שהוא ראה.
 *
 * זו לא רק אי-נוחות. run_command היא ההרשאה היחידה שגבול התיקייה אינו כולא,
 * והיא כבויה כברירת מחדל - כך שהפעולה נכשלת, והתיקון הטבעי של המשתמש הוא
 * להדליק בדיוק את ההרשאה המסוכנת ביותר, בשביל משימה שפעולה ייעודית הייתה
 * מבצעת בתוך התחום המותר.
 *
 * הרשימה כאן נגזרת מהשרת ולא מועתקת אליו, כדי שפעולה חדשה בשרת שלא פורסמה
 * בפרומפט תיפול כאן.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
let pass = 0, fail = 0;
const failures = [];

function check(name, condition, detail) {
  if (condition) { pass++; console.log('  [ok]   ' + name); }
  else { fail++; failures.push({ name, detail }); console.log('  [FAIL] ' + name + (detail ? '  -> ' + detail : '')); }
}

// ---- מה השרת באמת תומך בו ----
const serverSrc = fs.readFileSync(path.join(ROOT, 'bridge-server', 'server.js'), 'utf8');
const filesSrc = fs.readFileSync(path.join(ROOT, 'bridge-server', 'actions-files.js'), 'utf8');

// ה-case-ים בתוך handleWindowsExecute
const switchStart = serverSrc.indexOf('async function handleWindowsExecute');
const fromSwitch = serverSrc.slice(switchStart);
const cases = [...fromSwitch.matchAll(/case '([a-z_]+)':/g)].map((m) => m[1]);

// הפעולות שמודול הקבצים מוסיף: מפתחות ברמה העליונה של האובייקט המוחזר
const fileActions = [...filesSrc.matchAll(/^\s{4}([a-z_]+)\(params\)/gm)].map((m) => m[1]);

const serverActions = [...new Set([...cases, ...fileActions])].sort();

// ---- מה הפרומפט מפרסם ----
const promptSrc = fs.readFileSync(path.join(ROOT, 'prompt.js'), 'utf8');
const ctx = { window: {}, console: { log() {} } };
vm.createContext(ctx);
vm.runInContext(promptSrc, ctx);
const generate = ctx.generateOmniSystemPrompt || (ctx.window && ctx.window.generateOmniSystemPrompt);
const single = ctx.generateSingleToolPrompt || (ctx.window && ctx.window.generateSingleToolPrompt);

console.log('');
console.log('=== every server action is advertised ===');
console.log('  server exposes: ' + serverActions.join(', '));

const mainPrompt = generate(['windows']);
for (const action of serverActions) {
  check(`the main prompt mentions ${action}`, mainPrompt.includes(action));
}

console.log('');
console.log('=== the @-menu prompt covers the same ground ===');
const menuPrompt = single('windows', null, {}, 'do a thing');
for (const action of serverActions) {
  check(`the @-menu prompt mentions ${action}`, menuPrompt.includes(action));
}

console.log('');
console.log('=== run_command is steered away from ===');
check('the main prompt tells the model to prefer a dedicated action',
      /PREFER a dedicated action|PREFER the dedicated action/i.test(mainPrompt));
check('the @-menu prompt says the same',
      /PREFER a dedicated action|PREFER the dedicated action/i.test(menuPrompt));
check('it explains that run_command escapes the folder limit',
      /cannot contain|allowed-folder/i.test(mainPrompt));
check('creating a folder points at make_dir rather than New-Item',
      /make_dir,\s+not New-Item/i.test(mainPrompt));

console.log('');
console.log('=== multi-step plans are advertised ===');
check('the main prompt shows the plan shape', mainPrompt.includes('"plan"'));
check('it explains reference syntax', mainPrompt.includes('$name'));
check('it states that a plan asks once', /asks the user once/i.test(mainPrompt));
check('it warns that references cannot go inside run_command',
      /not allowed inside a run_command/i.test(mainPrompt));

console.log('');
console.log('================================================');
console.log('  ' + pass + ' passed, ' + fail + ' failed');
if (fail) {
  console.log('');
  console.log('  failures:');
  failures.forEach((f) => console.log('   - ' + f.name + (f.detail ? ' (' + f.detail + ')' : '')));
}
console.log('================================================');
console.log('');
process.exit(fail ? 1 : 0);
