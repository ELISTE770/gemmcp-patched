/**
 * מריץ תוכנית: רצף פעולות עם העברת ערכים ביניהן.
 *
 * למה זה קיים: עד עכשיו כל פקודה עמדה בפני עצמה, בלי זיכרון ובלי המשכיות.
 * משימה אמיתית - "מצא את כל ה-PDF-ים והעבר אותם לתיקייה" - דרשה עשרות סבבים
 * דרך הצ'אט, כשהמודל מקליד מחדש את התוצאה של כל שלב. כאן הרצף רץ בצד השרת.
 *
 * זה גם שיפור אבטחה ולא רק נוחות: המשתמש מאשר תוכנית אחת קריאה במקום עשרים
 * כרטיסים נפרדים, ועייפות אישורים היא הסכנה האמיתית בכלי כזה.
 *
 * הפניות בין שלבים:
 *   {"action":"find_files", "pattern":"*.pdf", "as":"pdfs"}
 *   {"action":"copy_file",  "from":"$pdfs[0].path", "to":"~/Docs"}
 *
 * נתמך: $name, $name.field, $name[i], ושרשור ביניהם. אין ביטויים ואין קוד -
 * רק שליפת ערך מתוך תוצאה קודמת.
 */

const MAX_STEPS = 40;

// שליפת ערך לפי נתיב כמו  pdfs[0].path  מתוך מפת התוצאות
function resolveReference(ref, results) {
  const body = ref.slice(1);                       // מסירים את ה-$
  const head = body.match(/^[A-Za-z_][A-Za-z0-9_]*/);
  if (!head) return undefined;

  let value = results[head[0]];
  let rest = body.slice(head[0].length);

  while (rest.length && value !== undefined && value !== null) {
    const idx = rest.match(/^\[(\d+)\]/);
    if (idx) {
      value = Array.isArray(value) ? value[Number(idx[1])] : undefined;
      rest = rest.slice(idx[0].length);
      continue;
    }
    const field = rest.match(/^\.([A-Za-z_][A-Za-z0-9_]*)/);
    if (field) {
      value = (typeof value === 'object') ? value[field[1]] : undefined;
      rest = rest.slice(field[0].length);
      continue;
    }
    break;                                          // תחביר לא מוכר - עוצרים
  }
  return value;
}

// החלפת הפניות בתוך הפרמטרים של שלב
function substitute(params, results) {
  if (params === null || params === undefined) return params;

  if (typeof params === 'string') {
    // מחרוזת שהיא כולה הפניה - מחזירים את הערך עצמו ולא טקסט
    if (/^\$[A-Za-z_][A-Za-z0-9_[\]().]*$/.test(params)) {
      const v = resolveReference(params, results);
      return v === undefined ? params : v;
    }
    // הפניה משובצת בתוך טקסט - הופכים למחרוזת
    return params.replace(/\$[A-Za-z_][A-Za-z0-9_[\]().]*/g, (m) => {
      const v = resolveReference(m, results);
      if (v === undefined) return m;
      return typeof v === 'object' ? JSON.stringify(v) : String(v);
    });
  }

  if (Array.isArray(params)) return params.map((x) => substitute(x, results));

  if (typeof params === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(params)) out[k] = substitute(v, results);
    return out;
  }

  return params;
}

/**
 * @param {Array}    steps      רשימת שלבים: { action, as?, ...params }
 * @param {Function} runAction  async (action, params) -> data ; זורק עם .status
 */
async function runPlan(steps, runAction) {
  if (!Array.isArray(steps) || steps.length === 0) {
    const e = new Error('התוכנית ריקה או אינה מערך.');
    e.status = 400;
    throw e;
  }
  if (steps.length > MAX_STEPS) {
    const e = new Error(`תוכנית ארוכה מדי: ${steps.length} שלבים, המקסימום ${MAX_STEPS}.`);
    e.status = 400;
    throw e;
  }

  const results = {};
  const log = [];

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i] || {};
    const action = step.action;
    if (!action) {
      const e = new Error(`שלב ${i + 1} חסר action.`);
      e.status = 400;
      throw e;
    }

    const { action: _a, as: alias, ...rawParams } = step;
    const params = substitute(rawParams, results);

    const started = Date.now();
    try {
      const data = await runAction(action, params);
      if (alias) results[alias] = data;
      log.push({ step: i + 1, action, alias: alias || null, ok: true, ms: Date.now() - started });
    } catch (err) {
      // עוצרים בכישלון הראשון. תוכנית שממשיכה אחרי שלב שנכשל תפעל על הנחות
      // שכבר אינן נכונות, וזה מסוכן יותר מלעצור.
      log.push({ step: i + 1, action, ok: false, ms: Date.now() - started, error: err.message });
      const e = new Error(`התוכנית נעצרה בשלב ${i + 1} (${action}): ${err.message}`);
      e.status = err.status || 500;
      e.partial = { completed: i, total: steps.length, log, results };
      throw e;
    }
  }

  return { completed: steps.length, total: steps.length, log, results };
}

module.exports = { runPlan, substitute, resolveReference, MAX_STEPS };
