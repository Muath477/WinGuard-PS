# WinGuard-PS — مرجع التشغيل والبنية التقنية

هذا الملف مرجع مختصر لـ **طريقة التشغيل**، **معاملات السكربت**، **هيكل المشروع**، **أوامر PowerShell المستخدمة**، و**جداول البيانات** (الكائنات، التقارير، السياسة).

**تنسيق النسخ:** كل أمر في **كتلة منفصلة**؛ انسخ محتوى الكتلة كاملاً (سطر واحد) ولصقه في PowerShell.

---

## 0. نسخ سريع — أوامر التشغيل

المسار الافتراضي للمشروع (عدّل إذا غيّرت مكان المجلد):

```powershell
cd "C:\Users\moath\OneDrive\Desktop\Smart System Auditor (SSA)\WinGuard-PS"
```

```powershell
.\WinGuard-PS.ps1
```

```powershell
.\WinGuard-PS.ps1 -Mode Quick
```

```powershell
.\WinGuard-PS.ps1 -Mode Deep
```

```powershell
.\WinGuard-PS.ps1 -Delta
```

```powershell
.\WinGuard-PS.ps1 -OpenReport
```

```powershell
.\WinGuard-PS.ps1 -OpenOnCritical
```

```powershell
.\WinGuard-PS.ps1 -Delta -OpenReport
```

```powershell
.\WinGuard-PS.ps1 -SkipBaselineUpdate
```

```powershell
.\WinGuard-PS.ps1 -Quiet
```

```powershell
.\WinGuard-PS.ps1 -FailOnCritical
```

```powershell
.\WinGuard-PS.ps1 -Quiet -FailOnCritical
```

إن ظهر منع تشغيل السكربتات، للجلسة الحالية فقط:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

## 1. متطلبات التشغيل

| البند | القيمة |
|--------|--------|
| نظام التشغيل | Windows 10 / 11 |
| PowerShell | 5.1 (Windows PowerShell) |
| الصلاحية | **Administrator** (إلزامي) |
| التنفيذ | إن لزم: انسخ الأمر من القسم **0** أعلاه |

---

## 2. طريقة التشغيل

### 2.1 فتح PowerShell كمسؤول

1. ابدأ → ابحث عن **PowerShell**  
2. كليك يمين → **Run as administrator**  
3. تأكّد من قبول UAC إن ظهرت

### 2.2 الانتقال للمجلد وتشغيل الأداة

انسخ كل سطر على حدة (أو استخدم القسم **0**):

```powershell
cd "C:\Users\moath\OneDrive\Desktop\Smart System Auditor (SSA)\WinGuard-PS"
```

```powershell
.\WinGuard-PS.ps1
```

### 2.3 معاملات السكربت (`WinGuard-PS.ps1`)

| المعامل | النوع | الوصف |
|---------|--------|--------|
| `-Mode` | `Quick` \| `Deep` | عمق الفحص: Quick أسرع مع حدود عينة؛ Deep أوسع (افتراضي: `Deep`) |
| `-Delta` | switch | مقارنة النتائج مع ملف baseline السابق (`Data\baseline.json`) |
| `-SkipBaselineUpdate` | switch | عدم تحديث ملف baseline بعد هذا التشغيل |
| `-OpenReport` | switch | فتح تقرير HTML في المتصفح بعد الانتهاء |
| `-OpenOnCritical` | switch | فتح HTML تلقائياً إذا وُجدت نتائج `Critical` |
| `-Quiet` | switch | تقليل مخرجات الكونسول؛ يطبع مسار تقرير HTML فقط في النهاية |
| `-FailOnCritical` | switch | إنهاء العملية برمز خروج **2** إذا وُجدت أي نتيجة `Critical` (مناسب للأتمتة) |

### رموز الخروج (Exit codes)

| الرمز | المعنى |
|--------|--------|
| `0` | نجاح الفحص والتصدير |
| `1` | فشل: ليست صلاحية Administrator |
| `2` | وُجدت نتائج Critical وتم استخدام `-FailOnCritical` |

**أمثلة (كل أمر في كتلة منفصلة للنسخ):**

```powershell
.\WinGuard-PS.ps1 -Mode Quick
```

```powershell
.\WinGuard-PS.ps1 -Delta -OpenReport
```

```powershell
.\WinGuard-PS.ps1 -OpenOnCritical
```

---

## 3. هيكل المشروع الملفات

| المسار | الدور |
|--------|--------|
| `WinGuard-PS.ps1` | نقطة الدخول: تحميل الوحدات، التحقق من Admin، تشغيل الفحص، التصدير |
| `Modules\Common\Utils.psm1` | نموذج النتيجة `Finding`، السجلات، البصمة، مساعدات النصوص |
| `Modules\Core\Core.Engine.psm1` | صلاحية Admin، تحميل السياسة، الدرجة، baseline، سياق المسارات |
| `Modules\Audit\Audit.Module.psm1` | فحص التصليح: UAC، جدار الحماية، المسؤولين، المنافذ، الخدمات |
| `Modules\Hunter\Hunter.Module.psm1` | بدء التشغيل، المهام المجدولة، الاتصالات |
| `Modules\Reporting\Reporting.Engine.psm1` | JSON، HTML، CSV، ملخص نصي |
| `Config\policy.json` | أوزان الخطورة، عتبات، منافذ، allowlist، أوضاع الفحص |
| `Rules\default.rules.json` | بيانات وصفية للقواعد (مرجعية) |
| `Data\baseline.json` | آخر خط أساس للمقارنة عند `-Delta` |
| `Reports\` | مخرجات التقارير لكل تشغيل |
| `Logs\` | سجلات JSONL لكل تشغيل |

---

## 4. تدفق التنفيذ (مختصر)

1. التحقق من **Administrator**  
2. تحميل `policy.json` و `default.rules.json`  
3. **Phase 1 — Audit:** UAC، Firewall، Local Admins، منافذ عالية الخطورة (مع دمج/تخفيض حسب السياسة)، خدمات التشغيل التلقائي  
4. **Phase 2 — Hunter:** مجلدات Startup، مهام مجدولة، لقطة اتصالات TCP  
5. تجميع النتائج وحساب **درجة الأمان** (Risk Score)  
6. تصدير: JSON، HTML، CSV، `summary.txt`، وتحديث baseline (ما لم يُستخدم `-SkipBaselineUpdate`)

---

## 5. كائن النتيجة (Finding)

كل فحص ينتج واحداً أو أكثر من الكائنات التالية (منطقياً):

| الحقل | النوع | المعنى |
|--------|--------|--------|
| `TimeUtc` | string (ISO 8601) | وقت توليد النتيجة |
| `Category` | string | مثل `Audit` أو `Hunter` |
| `CheckId` | string | معرف مثل `UAC-001`, `NET-PORT-135`, `HUNT-TASK-001` |
| `Severity` | string | `Critical` \| `Warning` \| `Pass` \| `Info` |
| `Title` | string | عنوان قصير |
| `Description` | string | تفاصيل (قد تتضمن أسطراً متعددة) |
| `Remediation` | string | توصية إصلاح |
| `Data` | hashtable/object | بيانات إضافية (منافذ، مسارات، ملفات، إلخ) |

---

## 6. هيكل التقرير JSON (رأسي)

| المفتاح | المحتوى |
|---------|---------|
| `Meta` | `Tool`, `Version`, `Timestamp`, `ScanMode`, `DurationSeconds`, `Delta` (إن وُجد) |
| `Summary` | `Score`, `Critical`, `Warning`, `Pass`, `Info`, `ScanTime`, `ScanMode`, `ComputerName`, `UserName`, `DurationSeconds`, `DurationHuman`, `ToolVersion` |
| `Findings` | مصفوفة من كائنات Finding |

---

## 7. ملف السياسة `Config\policy.json` (جدول الحقول)

### 7.1 weights — أوزان احتساب الخطورة

| المفتاح | المعنى |
|---------|--------|
| `critical` | وزن لكل نتيجة Critical |
| `warning` | وزن Warning |
| `info` | وزن Info |

### 7.2 thresholds

| المفتاح | المعنى |
|---------|--------|
| `localAdminWarningCount` | إذا كان عدد أعضاء مجموعة Administrators أكبر من هذا → Warning |

### 7.3 network

| المفتاح | المعنى |
|---------|--------|
| `highRiskPorts` | قائمة أرقام منافذ تُعتبر عالية الخطورة (مراقبة LISTEN) |
| `mergeListenersByPort` | دمج مستمعي نفس المنفذ في نتيجة واحدة |
| `downgradeWhenWindowsSystemBinary` | `enabled`, `ports`, `targetSeverity` — تخفيض الشدة لمسارات نظام معينة |

### 7.4 allowlist

| المفتاح | المعنى |
|---------|--------|
| `executablePathPrefixes` | بادئات مسارات تُعتبر موثوقة للمهام/startup |
| `taskPathContains` | إذا كان مسار المهمة يحتوي هذا النص → تُتجاهل من “مشبوه” |
| `portProcessAllow` | مصفوفة `{ "port", "processName" }` — تخفيض الشدة عند التطابق |

### 7.5 scanModes.quick / deep

| المفتاح | المعنى |
|---------|--------|
| `maxStartupFilesToHash` | حد أقصى لملفات بدء التشغيل المُجزَّأة (0 = بدون حد عملي في Deep) |
| `maxConnectionsSnapshot` | أقصى عدد صفوف في لقطة الاتصالات |
| `maxAutoStartServices` | أقصى عدد خدمات تُحلل في Quick (0 = الكل في Deep) |

### 7.6 hunter

| المفتاح | المعنى |
|---------|--------|
| `suspiciousRemotePorts` | قائمة أرقام منافذ بعيدة (في اتصالات Established نحو عناوين غير محلية)؛ عند التطابق تُرفع نتيجة لقطة الشبكة إلى Warning |

### 7.7 bitLocker

| المفتاح | المعنى |
|---------|--------|
| `mountPoints` | مصفوفة نقاط تركيب للتحقق من BitLocker (مثل `C:`) |

---

## 8. أوامر وواجهات PowerShell المستخدمة في الأداة

الجدول التالي يوضح **الأوامر/الواجهات** الشائعة حسب الوحدة (قد تختلف حسب إصدار Windows وصلاحيات الوصول).

### 8.1 Audit (تدقيق)

| الغرض | أمر / واجهة |
|--------|-------------|
| UAC | قراءة السجل: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` (`EnableLUA`) |
| جدار الحماية | `Get-NetFirewallProfile` |
| مجموعة المسؤولين المحلية | `Get-LocalGroupMember -Group Administrators` |
| المنافذ المفتوحة (LISTEN) | `Get-NetTCPConnection -State Listen` |
| مسار عملية | `Get-CimInstance Win32_Process` (PID → ExecutablePath) |
| توقيع ملف | `Get-AuthenticodeSignature` |
| عملية بالاسم | `Get-Process` |
| خدمات التشغيل التلقائي | `Get-CimInstance Win32_Service` (StartMode = Auto) |
| Defender | `Get-MpComputerStatus` |
| RDP / NLA | سجل `Terminal Server` و `WinStations\RDP-Tcp` |
| SMB1 | `Get-WindowsOptionalFeature -FeatureName SMB1Protocol` |
| BitLocker | `Get-BitLockerVolume` |
| WinRM | `Get-Service WinRM` |

### 8.2 Hunter (صيد)

| الغرض | أمر / واجهة |
|--------|-------------|
| ملفات Startup | `Get-ChildItem` على مجلدات Startup المعروفة |
| تجزئة الملف | `Get-FileHash -Algorithm SHA256` |
| مهام مجدولة | `Get-ScheduledTask`، قراءة `Actions` مع التحقق من وجود `Execute` |
| Run / RunOnce | `Get-ItemProperty` على مفاتيح `Run` و `RunOnce` في HKLM/HKCU (ومجلد WOW6432) |
| WMI persistence | `Get-CimInstance` على `CommandLineEventConsumer` و `ActiveScriptEventConsumer` في `root\subscription` |
| اتصالات TCP | `Get-NetTCPConnection`؛ تصنيف العناوين عبر `Test-WGIsExternalRemoteAddress` في `Utils.psm1` |

### 8.3 Core / Reporting

| الغرض | أمر / واجهة |
|--------|-------------|
| صلاحية مسؤول | `[Security.Principal.WindowsPrincipal]` / `IsInRole(Administrator)` |
| JSON | `ConvertTo-Json` / `ConvertFrom-Json` |
| CSV | `Export-Csv` |
| ملفات نصية | `Out-File` |

---

## 9. مخرجات التقارير (أسماء الملفات)

| النمط | المثال | الوصف |
|--------|--------|--------|
| JSON | `Reports\Audit_yyyyMMdd_HHmmss.json` | تقرير كامل قابل للمعالجة |
| HTML | `Reports\Audit_yyyyMMdd_HHmmss.html` | لوحة، جدول Findings، فلترة، ملخص تنفيذي |
| CSV | `Reports\Audit_yyyyMMdd_HHmmss.csv` | صفوف: Severity, Category, CheckId, Title, Description, Remediation |
| Summary | `Reports\Audit_yyyyMMdd_HHmmss.summary.txt` | نص مختصر: الدرجة، العدّادات، أولويات |
| Log | `Logs\Scan_yyyyMMdd_HHmmss.log.jsonl` | سطر JSON لكل حدث سجل |
| Baseline | `Data\baseline.json` | بصمات النتائج لآخر تشغيل (لـ Delta) |

---

## 10. جدول أعمدة CSV

| العمود | المحتوى |
|--------|---------|
| Severity | Critical / Warning / Pass / Info |
| Category | Audit / Hunter |
| CheckId | معرف الفحص |
| Title | عنوان |
| Description | وصف |
| Remediation | إصلاح مقترح |

---

## 11. درجة الأمان (Score)

- تُحسب من **أوزان** الشدة في `policy.json` وعدد النتائج (انظر `Get-WGRiskScore` في `Core.Engine.psm1`).
- الهدف: **100** = أقل عقوبة؛ القيم الأقل تعكس تراكم Critical/Warning/Info.

---

## 12. استكشاف الأخطاء السريع

| المشكلة | الحل |
|----------|------|
| `Administrator privileges are required` | شغّل PowerShell **Run as administrator** |
| `Cannot run script` | استخدم القسم **0** أو الأوامر تحت هذا الجدول |
| خطأ في خاصية `Execute` للمهام | في الإصدارات الحديثة: تجاهل إجراءات المهام غير `Exec` |
| تكرار منفذ في التقرير | فعّل `mergeListenersByPort` في `policy.json` |

**عند منع تشغيل السكربتات** — انسخ الأمر الأول، ثم الثاني:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

```powershell
.\WinGuard-PS.ps1
```

---

## 13. الإصدار

راجع حقل `Meta.Version` داخل ملف JSON؛ المرجع يصف السلوك العام لـ **WinGuard-PS** من الإصدار **1.3.x** فما فوق.

---

*للتفاصيل العامة، راجع `README.md` في نفس المجلد.*
