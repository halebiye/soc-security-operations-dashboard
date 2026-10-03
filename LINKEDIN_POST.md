# LinkedIn announcement drafts

Add the actual repository URL after publishing. Attach `portfolio/project-cover.png` or the desktop dashboard screenshot. These drafts describe a synthetic learning project, not professional SOC employment or confirmed real-world incidents.

## English

My second cybersecurity portfolio project: **SOC Security Operations Dashboard**.

I’m using this local Mini SIEM to practice the workflow from authentication telemetry to an evidence-based analyst investigation.

It includes:

- CSV/JSON ingestion with validation, deduplication, and SQLite persistence.
- Seven explainable rules covering failed login patterns, success after failures, privileged accounts, multiple targeted accounts, outside-hours activity, a synthetic watchlist, and authentication spikes.
- A dark SOC dashboard, full alert evidence, analyst notes, and New / Investigating / Closed case workflow.
- Filtered HTML, JSON, and Markdown investigation reports.
- Automated rule/API tests, real-browser checks, Docker configuration, and GitHub Actions.

The included synthetic dataset contains 553 events and produces 18 alerts, including two critical detections. The local verification passed 103 Pytest tests and 25 browser checks.

The lesson I want to demonstrate: a detection is a hypothesis. Its value comes from the evidence, context, and analyst decision—not just a severity badge.

Built as an AI-assisted learning project with Python, FastAPI, SQLite, JavaScript, and Chart.js. I’m continuing toward Junior SOC Analyst / Cybersecurity Analyst opportunities and working on explaining every part of the system clearly.

Repository: **[add the published GitHub URL]**

#Cybersecurity #SOC #BlueTeam #Python #SecurityOperations #LearningInPublic

## العربية

مشروعي الثاني ضمن ملف أعمال الأمن السيبراني: **SOC Security Operations Dashboard**.

المشروع عبارة عن Mini SIEM محلي، أستخدمه للتدرب على رحلة الحدث الأمني: من سجل تسجيل الدخول، إلى قاعدة الكشف، ثم التحقيق وتوثيق قرار المحلل.

يتضمن:

- استيراد CSV وJSON مع التحقق من البيانات ومنع التكرار وحفظها في SQLite.
- سبع قواعد كشف واضحة، منها تكرار فشل الدخول، نجاح الدخول بعد الفشل، الحسابات ذات الصلاحيات، واستهداف عدة حسابات.
- لوحة SOC، أدلة كل تنبيه، ملاحظات المحلل، وحالات New / Investigating / Closed.
- تقارير HTML وJSON وMarkdown واختبارات آلية وفحص فعلي للواجهة.

بيانات التدريب صناعية بالكامل: 553 حدثًا تنتج 18 تنبيهًا، منها تنبيهان Critical. نجح التحقق المحلي في 103 اختبارات Pytest و25 فحصًا بالمتصفح.

الفكرة التي أركز عليها: التنبيه يحتاج تحقيقًا وسياقًا، ولا يعني وحده أن اختراقًا حصل.

المشروع مبني بمساعدة الذكاء الاصطناعي باستخدام Python وFastAPI وSQLite وJavaScript وChart.js، مع دليل تعلّم يساعدني على فهم الكود وشرح قرارات التصميم. أواصل تطوير مهاراتي باتجاه أدوار Junior SOC Analyst وCybersecurity Analyst.

رابط GitHub: **[أضف الرابط بعد النشر]**

#Cybersecurity #SOC #BlueTeam #Python #SecurityOperations
