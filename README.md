<div dir="rtl">

# netfree-doctor

כלי שמאבחן בלחיצה אחת בעיות של "זה לא עובד בנטפרי", מסביר **בעברית** מה הבעיה, ומציע תיקונים בטוחים למחשב שלכם.

> **הכלי לא עוקף את הסינון.** הוא לא מציע VPN, פרוקסי, מנהרות DNS או כל דרך אחרת לעקוף את נטפרי, וגם לא מכבה בדיקות אבטחה.
> המטרה היא אחת: לגרום לדברים לעבוד **עם** נטפרי.

## למה צריך את זה?

נטפרי מסננת גם אתרים מוצפנים (HTTPS). לשם כך היא מציגה לכל אתר תעודה שהיא חתמה עליה, ולכן המחשב צריך לסמוך על **תעודת השורש של נטפרי**.
הדפדפן משתמש במאגר התעודות של Windows, אבל הרבה תוכנות מחזיקות מאגר תעודות משלהן. לכן הן נכשלות עם שגיאות כמו
`UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, `SELF_SIGNED_CERT_IN_CHAIN`, `CERTIFICATE_VERIFY_FAILED` או `SSL certificate problem`.
זה קורה למשל ב-Node/npm, Python/pip, Git, Java, Firefox ובאמולטורים של אנדרואיד.

## איך מריצים

דרישות: Windows 10/11 ו-Node.js 20 ומעלה.

```bash
npm install
npm run build

# כל הבדיקות (פלט בעברית)
node dist/cli/index.js

# בדיקת כתובת אחת: DNS, חיבור, תעודה, תשובת HTTP, חסימה והערות של נטפרי
node dist/cli/index.js check https://chatgpt.com
node dist/cli/index.js check wss://example.com/socket

# תיקונים
node dist/cli/index.js fix                      # רשימת התיקונים
node dist/cli/index.js fix node-extra-ca --dry-run   # רק להציג מה ייעשה
node dist/cli/index.js fix node-extra-ca        # מציג, שואל לאישור ואז מבצע
node dist/cli/index.js undo                     # ביטול התיקון האחרון
node dist/cli/index.js undo --list              # יומן התיקונים

# ממשק גרפי (חלון עם כרטיסים וכפתור "תקן")
npm run gui
```

אפשרויות: `--en` (אנגלית), `--json` (פלט JSON), `--yes` (בלי שאלת אישור), `--dry-run`, `--only node,git`, `--verbose`, `--no-color`.
קוד היציאה הוא `0` כשאין תקלות ו-`2` כשנמצאה תקלה, כך שאפשר להשתמש בכלי גם בסקריפטים.

אחרי `npm link` (או התקנה גלובלית) הפקודה זמינה גם בשם `netfree-doctor`.

## הבדיקות

| # | מזהה | מה נבדק | תיקון |
|---|------|---------|-------|
| 1 | `netfree` | האם החיבור עובר דרך נטפרי. מתחברים ב-TLS ל-`www.google.com`, `github.com` ו-`pypi.org` ובודקים מי הנפיק את התעודה (למשל `NetFree Node Intermediate CA`), ועד איזו תעודת שורש מגיעה השרשרת. | (אין) |
| 2 | `windows-store` | האם תעודות השורש הרשמיות של נטפרי מותקנות ב-`CurrentUser\Root` או ב-`LocalMachine\Root`. הקריאה נעשית דרך PowerShell `Get-ChildItem Cert:\`, וההתאמה לפי טביעת אצבע (ואם אין, לפי שם). התעודות הרשמיות יורדות מ-`netfree.link/cacert/united/` (שני הדורות, כולל X2) ונשמרות בעותק מקומי. | הפניה למדריך הרשמי בלבד. התקנת תעודת שורש היא פעולה רגישה, ולכן הכלי לא עושה אותה בעצמו. |
| 3 | `firefox` | זיהוי פרופילים של Firefox ובדיקה אם `security.enterprise_roots.enabled` מופעל ב-`prefs.js` או ב-`user.js`. | `firefox-enterprise-roots`: כותב את ההגדרה ל-`user.js` (צריך לסגור את Firefox קודם). |
| 4 | `node` | האם `NODE_EXTRA_CA_CERTS` מוגדר ומצביע לקובץ שמכיל את תעודות נטפרי, האם ה-`cafile` של npm מכסה אותן, והאם הוגדר בטעות `strict-ssl=false`. | `node-extra-ca`: כותב קובץ PEM משולב אל `%USERPROFILE%\.netfree-doctor\netfree-ca.pem` (כולל התעודות שכבר היו בקובץ הקיים) ומגדיר משתנה סביבה של המשתמש עם `setx`. |
| 5 | `python` | איתור Python (`py -0p`, `where python`), ‏`pip config` (`global.cert`), ‏`REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`, ובדיקות חיבור אמיתיות: pip (‏`pip index versions`), ‏requests, ‏certifi ומאגר המערכת. מזהה גם את בעיית Python 3.13 ומעלה (ראו בהמשך). | `python-pip-cert`: יוצר קובץ משולב (certifi + נטפרי) ומגדיר `pip config --user set global.cert`. חלופה: `pip-system-certs` או `truststore`. |
| 6 | `git` | ‏`http.sslBackend` (‏`schannel` = מאגר Windows, וזה מצוין), ‏`http.sslCAInfo`, ‏`http.sslVerify=false` (מסוכן), ובמקרה הצורך גם `git ls-remote` אמיתי. | `git-schannel`: ‏`git config --global http.sslBackend schannel`, ומסיר `sslVerify=false` אם הוגדר. |
| 7 | `java` | איתור Java (‏`JAVA_HOME`, ‏`where java`) והסבר: פקודת `keytool -importcert` המדויקת, או `-Djavax.net.ssl.trustStoreType=Windows-ROOT`. | הסבר בלבד |
| 8 | `android` | איתור LDPlayer (‏`C:\LDPlayer\*\ldconsole.exe`), האמולטור של Android Studio ו-BlueStacks. ההסבר: מאנדרואיד 7 אפליקציות מתעלמות מתעודות משתמש, ותעודת מערכת דורשת root ומודול Magisk ([אנדרואיד 14](https://github.com/Sivan22/ca-netfree-android14/releases), [גרסאות קודמות](https://github.com/Sivan22/ca-netfree)). | הסבר בלבד. הכלי לא מבצע root. |
| - | `check <url>` | ‏DNS, ‏TCP, ‏TLS (מי הנפיק את התעודה והאם Node סומך עליה), ותשובת HTTP. מזהה **דף חסימה** (קוד 418 עם `netfree.link/block/#...`), מציג את סיבת החסימה עם הסבר בעברית, ונותן קישור לדף החסימה, שממנו אפשר לשלוח בקשה. מזהה גם **הערות שנטפרי מוסיפה לאתר** (למשל ב-chatgpt.com) וממיר קישורי ויקי `[[דף\|טקסט]]` לכתובות `https://netfree.link/wiki/דף`. בכתובות `ws://`/`wss://` נבדקת גם לחיצת היד של WebSocket. | (אין) |

סיבות חסימה מוכרות (שנצפו בפועל): `deny`, `unknown` (האתר עוד לא נבדק), `special-site` (למשל יוטיוב), `risk-type` (למשל קריאת API). סיבה שהכלי לא מכיר מוצגת כמו שהיא.

### ממצא חשוב: Python 3.13 ומעלה

החל מ-Python 3.13 מופעלת כברירת מחדל בדיקת X.509 מחמירה (`VERIFY_X509_STRICT`).
תעודת השורש של נטפרי שבשימוש כרגע (`NetFree Root CA 1990-2200 RSA`) **חסרה את ההרחבה Key Usage**, ולכן Python דוחה אותה עם השגיאה
`CA cert does not include key usage extension`, גם כשהיא מוגדרת נכון ב-`REQUESTS_CA_BUNDLE`.
pip עדיין עובד, כי מגרסה 24.2 הוא משתמש במאגר של Windows דרך truststore, אבל requests ו-urllib נכשלים.
במצב כזה הכלי לא מציע תיקון חסר תועלת. הוא ממליץ על `pip install pip-system-certs` או על `truststore.inject_into_ssl()`, שמאמתים מול Windows. תעודות ה-X2 החדשות של נטפרי כוללות Key Usage.

## עקרונות בטיחות

* **רק הגדרות של המשתמש הנוכחי:** משתני סביבה של המשתמש, `user.js`, ‏`pip config --user`, ‏`git config --global` ו-`npm config`. אין שינוי בהגדרות המחשב כולו ואין צורך בהרשאות מנהל.
* **dry-run לכל תיקון:** לפני ביצוע מוצג בדיוק מה ייכתב ואיזו פקודה תרוץ, כולל פקודת הביטול. לפני ביצוע תמיד נשאלת שאלת אישור, אלא אם הועבר `--yes`.
* **גיבוי ויומן:** כל קובץ מגובה לפני שינוי (‏`%USERPROFILE%\.netfree-doctor\backups\`), וכל שלב נרשם ב-`journal.json`. הפקודה `netfree-doctor undo` מחזירה את המצב הקודם: משחזרת קבצים, מוחקת קבצים שלא היו קיימים לפני, ומחזירה את הערכים הקודמים של משתנים והגדרות.
* **אין כיבוי של אימות TLS. לעולם.** כל תוכנית תיקון נבדקת מול רשימה של "פתרונות" אסורים, ותיקון שמכיל אחד מהם נדחה:
  * `NODE_TLS_REJECT_UNAUTHORIZED=0`
  * `git config http.sslVerify false`
  * `npm config set strict-ssl false`
  * `pip --trusted-host`, ‏`verify=False`, ‏`PYTHONHTTPSVERIFY=0`
  * `curl -k` / `--insecure`
  * כל VPN, פרוקסי או SOCKS

  **אלה התיקונים השגויים שממליצים עליהם הרבה פעמים בפורומים.** הם "עובדים" כי הם מבטלים לגמרי את בדיקת האבטחה, ומשאירים את המחשב חשוף להתחזות. אם כבר הגדרתם אחד מהם, הכלי יתריע ויציע להחזיר את הבדיקה.
* **כתיבה רק בתוך תיקיית המשתמש.** תיקון שמנסה לכתוב מחוץ ל-`%USERPROFILE%` נדחה.
* **תעודות מוצמדות:** התעודות שיורדות מ-netfree.link מתקבלות רק אם טביעת האצבע (SHA-256) שלהן מופיעה ברשימה קבועה בקוד, או אם ההורדה עברה בחיבור מאומת.
* **בדיקת כתובת אינה עוקפת דבר:** בקשת ה-GET האבחונית לא שולחת עוגיות או פרטי התחברות. היא קוראת את התשובה גם כש-Node עוד לא סומך על נטפרי, כדי שאפשר יהיה לזהות דף חסימה, והעובדה ש-Node לא סומך על התעודה מדווחת בנפרד.

## מבנה הקוד

```
src/core/       מנוע בדיקות טהור: כל בדיקה היא { id, titleHe, run(ctx) }
  checks/       הבדיקות
  parsers/      דף חסימה, הערות ויקי, תעודות, prefs של Firefox, JSON של PowerShell, פלט Python
  fixes/        הגדרות תיקון (plan), מבצע עם גיבוי, יומן וביטול, ובדיקת בטיחות
  urlCheck.ts   בדיקת כתובת בודדת
src/platform/   המימוש האמיתי של ctx (רשת, קבצים, PowerShell, רישום)
src/cli/        שורת הפקודה
src/gui/        ממשק Electron מינימלי, ללא אינטרנט וללא CDN
test/           בדיקות vitest עם ctx מזויף ונתונים אמיתיים שנאספו מנטפרי
```

פיתוח: `npm run typecheck`, `npm run lint`, `npm test`, `npm run build`.

</div>

---

## English

**netfree-doctor** diagnoses "doesn't work on Netfree" problems in one click and explains them in Hebrew (`--en` for English).
Netfree is an Israeli filtering ISP that inspects HTTPS with its own root CAs. Browsers that use the Windows store are fine, but tools with
their own CA stores (Node/npm, Python, Git, Java, Firefox, Android emulators) fail with TLS errors.

* `netfree-doctor` runs all checks. `check <url>` diagnoses one URL (DNS → TCP → TLS issuer → HTTP, 418 block-page reason, injected Netfree notes, and the WebSocket upgrade for `wss://`).
* `fix <id>` applies one fix after showing a dry-run and asking for confirmation. `undo` reverts it from backups and the journal.
* `npm run gui` opens a small offline Electron window (RTL Hebrew) with result cards and a "fix" button.

**It never bypasses the filter** (no VPN/proxy/tunnel advice) and **never disables TLS verification**. `NODE_TLS_REJECT_UNAUTHORIZED=0`,
`http.sslVerify false`, `strict-ssl false`, `--trusted-host` and `verify=False` are the common *wrong* fixes, and the tool refuses to apply them.
Fixes only change per-user configuration, back up every file first, and can all be undone.

Notable finding: Python 3.13+ enables `VERIFY_X509_STRICT`, and Netfree's currently used root (`NetFree Root CA 1990-2200 RSA`) has no Key Usage
extension, so `requests`/`urllib` fail even when correctly configured. The tool detects this and recommends `pip-system-certs` / `truststore`.

License: MIT © ayal408
