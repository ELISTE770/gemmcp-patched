/**
 * בדיקות ליכולות שנוספו: פעולות קבצים, עימוד, והרצת תוכניות.
 * מריצים מול שרת חי:  npm run test:caps
 *
 * הבדיקות עובדות בתוך תיקיית עבודה זמנית מתחת לשולחן העבודה, כדי להישאר
 * בתוך תקרת WIN_ALLOWED_PATH ולא לגעת בקבצים אמיתיים.
 */
const fs = require('fs');
const path = require('path');

const BASE = 'http://127.0.0.1:3000';
const HOME = process.env.USERPROFILE || process.env.HOME;
// נגזר מהשרת בזמן ריצה, ראה למטה
let DESKTOP = path.join(HOME, 'Desktop');
let WORK = path.join(DESKTOP, '_gemmcp_test');

let TOKEN = '';
try { TOKEN = fs.readFileSync(path.join(__dirname, '..', '.token'), 'utf8').trim(); } catch (e) {}

let pass = 0, fail = 0;
const failures = [];

function check(name, condition, detail) {
  if (condition) { pass++; console.log('  [ok]   ' + name); }
  else { fail++; failures.push({ name, detail }); console.log('  [FAIL] ' + name + (detail ? '  -> ' + detail : '')); }
}


// החבילה עצמה מייצרת יותר מ-40 בקשות בחלון של 10 שניות, ולכן חוטפת 429 מהלימיטר
// האמיתי. במקום להחליש את ההגנה לצורך הבדיקות, מחכים ומנסים שוב - כך הלימיטר
// נשאר בתוקף גם בזמן שהבדיקות רצות.
async function withRateLimitRetry(fn) {
  let out = await fn();
  if (out && out.status === 429) {
    await new Promise((r) => setTimeout(r, 10500));
    out = await fn();
  }
  return out;
}

async function postOnce(pathname, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (TOKEN) headers['x-bridge-token'] = TOKEN;
  const res = await fetch(BASE + pathname, { method: 'POST', headers, body: JSON.stringify(body) });
  let json = null;
  try { json = await res.json(); } catch (e) {}
  return { status: res.status, json };
}

const post = (pathname, body) => withRateLimitRetry(() => postOnce(pathname, body));
const run = (action, params) => post('/api/windows/execute', { action, params });
const plan = (steps) => post('/api/windows/plan', { plan: steps });

(async () => {
  const pre = await (await fetch(BASE + '/api/health')).json();
  if (pre.permissions && pre.permissions.allowedPath && pre.permissions.allowedPath !== '*') {
    DESKTOP = pre.permissions.allowedPath;
    WORK = path.join(DESKTOP, '_gemmcp_test');
  }

  // ניקוי מצב קודם והכנת סביבת עבודה
  fs.rmSync(WORK, { recursive: true, force: true });
  fs.mkdirSync(WORK, { recursive: true });
  fs.writeFileSync(path.join(WORK, 'alpha.txt'), 'alpha contents');
  fs.writeFileSync(path.join(WORK, 'beta.txt'), 'beta contents');
  fs.writeFileSync(path.join(WORK, 'notes.md'), 'markdown');

  const health = (await (await fetch(BASE + '/api/health')).json());
  const canWrite = health.permissions && health.permissions.writeFiles;

  console.log('');
  console.log('=== pagination ===');
  const ls = await run('list_directory', { path: WORK, limit: 2 });
  check('list_directory reports total and hasMore',
        ls.json.data.total === 3 && ls.json.data.returned === 2 && ls.json.data.hasMore === true,
        JSON.stringify({ total: ls.json.data.total, returned: ls.json.data.returned, hasMore: ls.json.data.hasMore }));
  const ls2 = await run('list_directory', { path: WORK, offset: 2, limit: 2 });
  check('list_directory second page completes the set',
        ls2.json.data.returned === 1 && ls2.json.data.hasMore === false);

  const rf = await run('read_file', { path: path.join(WORK, 'alpha.txt'), limit: 5 });
  check('read_file honours a read window',
        rf.json.data.content === 'alpha' && rf.json.data.hasMore === true,
        JSON.stringify(rf.json.data.content));
  const rf2 = await run('read_file', { path: path.join(WORK, 'alpha.txt'), offset: 5, limit: 100 });
  check('read_file second window reaches the end',
        rf2.json.data.content === ' contents' && rf2.json.data.hasMore === false);

  console.log('');
  console.log('=== find_files ===');
  const ff = await run('find_files', { path: WORK, pattern: '*.txt' });
  check('find_files matches a glob', ff.json.data.total === 2, 'total=' + (ff.json.data && ff.json.data.total));
  const ffPage = await run('find_files', { path: WORK, pattern: '*', limit: 1 });
  check('find_files paginates', ffPage.json.data.returned === 1 && ffPage.json.data.hasMore === true);
  const ffOut = await run('find_files', { path: 'C:/Windows', pattern: '*.exe' });
  check('find_files respects the path ceiling', !(ffOut.json && ffOut.json.success), 'status ' + ffOut.status);

  console.log('');
  console.log('=== file mutations (' + (canWrite ? 'writes enabled' : 'writes disabled - expecting 403') + ') ===');
  const mk = await run('make_dir', { path: path.join(WORK, 'sub') });
  const cp = await run('copy_file', { from: path.join(WORK, 'alpha.txt'), to: path.join(WORK, 'sub') });
  const mv = await run('move_file', { from: path.join(WORK, 'beta.txt'), to: path.join(WORK, 'sub') });

  if (canWrite) {
    check('make_dir creates a directory', mk.json.success === true && fs.existsSync(path.join(WORK, 'sub')));
    check('copy_file copies into a directory target',
          cp.json.success === true && fs.existsSync(path.join(WORK, 'sub', 'alpha.txt')));
    check('copy_file leaves the source in place', fs.existsSync(path.join(WORK, 'alpha.txt')));
    check('move_file moves and removes the source',
          mv.json.success === true &&
          fs.existsSync(path.join(WORK, 'sub', 'beta.txt')) &&
          !fs.existsSync(path.join(WORK, 'beta.txt')));
    const clash = await run('copy_file', { from: path.join(WORK, 'alpha.txt'), to: path.join(WORK, 'sub', 'alpha.txt') });
    check('copy_file refuses to overwrite without overwrite=true', clash.status === 409, 'got ' + clash.status);
  } else {
    check('make_dir is gated by writeFiles', mk.status === 403);
    check('copy_file is gated by writeFiles', cp.status === 403);
    check('move_file is gated by writeFiles', mv.status === 403);
  }

  const escape = await run('copy_file', { from: path.join(WORK, 'alpha.txt'), to: 'C:/Windows/evil.txt' });
  check('copy_file cannot write outside the ceiling', !(escape.json && escape.json.success), 'status ' + escape.status);

  console.log('');
  console.log('=== hostile input (findings from the adversarial review) ===');

  // רצף כוכביות תרגם ל-'.*.*.*' וגרם ל-backtracking קטסטרופלי שהקפיא את הגשר
  const t0 = Date.now();
  const redos = await run('find_files', { path: WORK, pattern: '*'.repeat(40) + 'x' });
  const elapsed = Date.now() - t0;
  check('a pathological glob does not hang the bridge', elapsed < 3000, elapsed + 'ms');
  check('the bridge is still responsive afterwards',
        (await (await fetch(BASE + '/api/health')).json()).status === 'ok');

  // הפניות שנפתרו דרך שרשרת הפרוטוטייפ שלפו אובייקטים והכניסו אותם לפרמטרים
  const protoRef = await plan([
    { action: 'list_directory', path: WORK, as: 'listing' },
    { action: 'read_file', path: '$listing.constructor' }
  ]);
  check('a $constructor reference cannot pull a host object into a parameter',
        protoRef.json.success === false, JSON.stringify(protoRef.json && protoRef.json.error));

  const protoAlias = await plan([{ action: 'list_directory', path: WORK, as: '__proto__' }]);
  check('an alias named __proto__ is rejected outright',
        protoAlias.status === 400, 'got ' + protoAlias.status);

  console.log('');
  console.log('=== plans ===');
  const empty = await plan([]);
  check('empty plan is rejected', empty.status === 400);

  const tooLong = await plan(Array.from({ length: 50 }, () => ({ action: 'list_directory', path: WORK })));
  check('over-long plan is rejected', tooLong.status === 400, 'got ' + tooLong.status);

  const seq = await plan([
    { action: 'list_directory', path: WORK, as: 'listing' },
    { action: 'read_file', path: path.join(WORK, 'notes.md'), as: 'note' }
  ]);
  check('multi-step plan runs every step',
        seq.json.success === true && seq.json.data.completed === 2,
        JSON.stringify(seq.json && seq.json.error));
  check('plan keeps each step result under its alias',
        seq.json.data.results.listing && seq.json.data.results.note &&
        seq.json.data.results.note.content === 'markdown');

  // הפניה בין שלבים: התוצאה של שלב אחד מזינה את הבא
  const ref = await plan([
    { action: 'find_files', path: WORK, pattern: '*.md', as: 'found' },
    { action: 'read_file', path: '$found.items[0].path', as: 'body' }
  ]);
  check('plan passes a value from one step into the next',
        ref.json.success === true && ref.json.data.results.body.content === 'markdown',
        JSON.stringify(ref.json && (ref.json.error || ref.json.data.results.body)));

  const halt = await plan([
    { action: 'list_directory', path: WORK, as: 'ok' },
    { action: 'read_file', path: path.join(WORK, 'does-not-exist.txt') },
    { action: 'list_directory', path: WORK }
  ]);
  check('plan stops at the first failing step',
        halt.json.success === false && halt.json.partial && halt.json.partial.completed === 1,
        JSON.stringify(halt.json && halt.json.partial && halt.json.partial.completed));
  check('failed plan reports which step broke',
        halt.json.partial.log.length === 2 && halt.json.partial.log[1].ok === false);

  const planEscape = await plan([{ action: 'list_directory', path: 'C:/Windows' }]);
  check('plan steps obey the same path ceiling', planEscape.json.success === false);

  // ניקוי
  fs.rmSync(WORK, { recursive: true, force: true });

  console.log('');
  console.log('================================================');
  console.log('  ' + pass + ' passed, ' + fail + ' failed');
  if (fail) {
    console.log('');
    console.log('  failures:');
    failures.forEach(f => console.log('   - ' + f.name + (f.detail ? ' (' + f.detail + ')' : '')));
  }
  console.log('================================================');
  console.log('');
  process.exit(fail ? 1 : 0);
})();
