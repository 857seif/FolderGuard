<div align="center">

<img src="https://raw.githubusercontent.com/yourusername/FolderGuard/main/assets/banner.png" width="800" alt="FolderGuard Ultimate Banner">

# 🛡️ FolderGuard Ultimate
### RenPy & Amatera Stealer Killer | Real-Time Windows Defense

[![Stage](https://img.shields.io/badge/Stage-Early%20Alpha-red?style=for-the-badge&logo=windows)]()
[![Language](https://img.shields.io/badge/C%2B%2B-Win32-blue?style=for-the-badge&logo=c%2B%2B)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)]()

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=700&size=22&pause=1000&color=00FF88&center=true&vCenter=true&width=600&lines=Killing+the+Fake+Game+Chain;RenPy+Loader+%E2%86%92+MSBuild+%E2%86%92+Amatera;Real-Time+Sysmon+Hook;Firewall+Drop+%2B+Quarantine" alt="Typing SVG" />
</p>

</div>

---

## 🌐 Languages | Языки | اللغات

- [🇺🇸 English](#english)
- [🇷🇺 Русский](#russian)
- [🇸🇦 العربية](#arabic)

---

<div id="english"></div>

## 🇺🇸 English

### ⚔️ What is FolderGuard?

**FolderGuard Ultimate** is a real-time, kernel-assisted defense tool built to dismantle the **Fake Game → RenPy Loader → MSBuild → Amatera Stealer** infection chain before it touches your credentials.

It hooks **Sysmon Event IDs 1, 3, 7, 8, 10, 11, 13, 25** and kills the threat at **Stage 1–4** — long before the stealer exfiltrates your accounts.

> 🚧 **STAGE: EARLY ALPHA** — Work in Progress. Getting stronger every commit.

---

### 🎯 The Attack Chain (What We Kill)

| Stage | Component | What Happens | FolderGuard Response |
|-------|-----------|--------------|---------------------|
| 1 | **Fake Download** | User downloads a "game" or "crack" | Monitors download directories |
| 2 | **Setup.exe** | Drops RenPy-based loader disguised as visual novel | **Blanket Ren'Py block** |
| 3 | **RenPy Loader** | Uses `forfiles.exe` to proxy-execute next stage | **LOLBin heuristic kill** |
| 4 | **MSBuild + EtherHiding** | Trojanized .NET project compiled on-the-fly, payload hidden in blockchain metadata | **MSBuild abuse detection** |
| 5 | **Amatera Stealer** | In-memory .NET injector harvests browsers, Discord, crypto wallets | **Killed before execution** |
| 6 | **Accounts at Risk** | Everything uploaded to C2 | **Never happens** |
<img width="756" height="394" alt="image" src="https://github.com/user-attachments/assets/ff8395a8-58cd-4f87-b5f2-1b77078d6673" />


# how this virus look like to take care of it
<img width="214" height="412" alt="image" src="https://github.com/user-attachments/assets/8cbf1866-4ac0-45c4-8194-3e68a89b310f" />



---

### 🧬 Core Detection Logic

#### 1. Blanket Ren'Py Block
Any executable sitting next to a `renpy\` folder, `lib\python3*.dll`, or `game\*.rpa` is killed instantly. This is a **deliberate policy choice**: we accept false positives on legitimate visual novels to guarantee zero Amatera loaders survive.

```cpp
// Signature-based hard block — no hash needed
static bool isRenPyExecutable(const std::string& fullPath) {
    // Signature 1: sibling "renpy" runtime folder
    if (PathFileExistsA((dir + "\\renpy").c_str())) return true;

    // Signature 2: lib\python3*.dll (CPython embedded by Ren'Py)
    std::string libDir = dir + "\\lib";
    if (PathFileExistsA(libDir.c_str())) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((libDir + "\\*python3*.dll").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) { FindClose(h); return true; }
    }

    // Signature 3: game\*.rpa or *.rpyc archives
    std::string gameDir = dir + "\\game";
    if (PathFileExistsA(gameDir.c_str())) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((gameDir + "\\*.rpa").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) { FindClose(h); return true; }
    }
    return false;
}
```

#### 2. LOLBin Abuse Heuristics
MSBuild or `forfiles.exe` running from `\Temp\`, `\Downloads\`, or `\AppData\` with suspicious command lines triggers immediate termination.

```cpp
// Specifically targets: RenPy Loader -> forfiles -> MSBuild -> trojanized .NET
static bool looksLikeMsBuildAbuse(const std::string& image, const std::string& cmdLine) {
    std::string img = toLower(image);
    std::string c = toLower(cmdLine);
    bool isMsBuild = img.find("\\msbuild.exe") != std::string::npos;
    bool isForfiles = img.find("\\forfiles.exe") != std::string::npos;
    if (!isMsBuild && !isForfiles) return false;

    bool fromUntrustedLoc =
        c.find("\\temp\\") != std::string::npos ||
        c.find("\\appdata\\local\\temp\\") != std::string::npos ||
        c.find("\\downloads\\") != std::string::npos;

    // MSBuild invoked outside dev context from user-writable folder = kill
    if (isMsBuild && fromUntrustedLoc) return true;
    if (isForfiles && (c.find("/c ") != std::string::npos) && fromUntrustedLoc) return true;
    return false;
}
```

#### 3. Recursive Process Tree Kill
Malware chains spawn multiple generations. Killing only the flagged PID leaves later stages running.

```cpp
// Recursively terminate all descendants (children, grandchildren, ...)
static void killProcessTreeRecursive(DWORD parentPid, int depth = 0) {
    if (depth > 8) return; // safety bound
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    std::vector<DWORD> children;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ParentProcessID == parentPid)
                children.push_back(pe.th32ProcessID);
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    for (DWORD childPid : children) {
        killProcessTreeRecursive(childPid, depth + 1);
        HANDLE hChild = OpenProcess(PROCESS_TERMINATE, FALSE, childPid);
        if (hChild) { TerminateProcess(hChild, 1); CloseHandle(hChild); }
    }
}
```

#### 4. Live Network Cut (Firewall Drop)
Before the process dies, a Windows Firewall rule blocks **all outbound/inbound** traffic for that binary path. Even if a child respawns, it cannot phone home.

```cpp
// Race against exfiltration
static void blockNetworkForImage(const std::string& fullPath) {
    std::string ruleName = "FolderGuard_Block_" + baseName(fullPath);
    std::string cmdOut = "netsh advfirewall firewall add rule name=\"" + ruleName +
        "\" dir=out action=block program=\"" + fullPath + "\" enable=yes";
    // ... execute silently
}
```

#### 5. Registry Persistence Sweep
Every 10 minutes we scan `HKCU\...\Run`, `HKLM\...\Run`, and WOW6432Node for entries pointing at Temp/Downloads/AppData binaries. Found? Registry value deleted, file quarantined.

---

### 📁 Required Directory Structure

FolderGuard expects its workspace at:

```
C:\ProgramData\FolderGuard\
├── watchdog.log          # Live event stream
├── Quarantine\           # Killed binaries land here (.quarantined)
├── hashes.txt            # SHA256 blocklist (hot-reload every 5 min)
└── data.bin              # Scan cache (mtime+size fingerprint)
```

> ⚠️ **Auto-created on first launch. Requires Administrator privileges.**

---

### 🧪 What Happens If You Run the Malware?

With FolderGuard **armed**:

1. Fake `Setup.exe` spawns → **Sysmon Event 1 fires** → `isRenPyExecutable()` returns `true` → **KILL + QUARANTINE** within milliseconds.
2. Loader proxies through `forfiles` → **LOLBin heuristic hits** → same fate.
3. `MSBuild` starts compiling a trojanized `.csproj` from Downloads → **MSBuild abuse trigger** → tree killed, firewall rule added.
4. DLL sideload happens (Event 7) from Temp → **instant termination**.
5. Stealer tries LSASS access (Event 10) → **dead on arrival**.
6. Process tampering / hollowing (Event 25) → **caught and killed**.

**Result:** Your browser vaults, Discord tokens, Telegram sessions, and crypto wallets never leave the machine.

---

### 🚀 Roadmap

| Version | Features |
|---------|----------|
| **v0.1 (Current)** | Live Sysmon hook, Ren'Py blanket block, LOLBin heuristics, recursive tree kill, firewall drop, registry sweep, Quick Scan, Full Disk Scan |
| **v0.2** | YARA memory scanning, inline hook detection, AMSI integration |
| **v0.3** | Kernel callback driver (minifilter) for filesystem-level pre-execution blocking |
| **v1.0** | Full EDR-grade telemetry, threat-hunting dashboard, Sigma rule engine |

---

<div id="russian"></div>

## 🇷🇺 Русский

### ⚔️ Что такое FolderGuard?

**FolderGuard Ultimate** — это инструмент защиты реального времени с поддержкой ядра, созданный для уничтожения цепочки заражения **Fake Game → RenPy Loader → MSBuild → Amatera Stealer** до того, как она коснётся ваших учётных данных.

Он перехватывает **Sysmon Event IDs 1, 3, 7, 8, 10, 11, 13, 25** и уничтожает угрозу на **этапах 1–4** — задолго до эксфильтрации аккаунтов.

> 🚧 **СТАДИЯ: РАННЯЯ АЛЬФА** — Активная разработка. Становится сильнее с каждым коммитом.

---

### 🎯 Цепочка атаки (что мы убиваем)

| Этап | Компонент | Что происходит | Ответ FolderGuard |
|------|-----------|----------------|-------------------|
| 1 | **Фейковая загрузка** | Пользователь скачивает «игру» или «кряк» | Мониторинг директорий загрузок |
| 2 | **Setup.exe** | Сбрасывает RenPy-загрузчик | **Полный блок Ren'Py** |
| 3 | **RenPy Loader** | Использует `forfiles.exe` для прокси-запуска | **Эвристика LOLBin** |
| 4 | **MSBuild + EtherHiding** | Троянизированный .NET-проект компилируется на лету | **Детекция MSBuild abuse** |
| 5 | **Amatera Stealer** | .NET-инжектор собирает браузеры, Discord, криптокошельки | **Убит до выполнения** |
| 6 | **Аккаунты под угрозой** | Всё загружается на C2 | **Не происходит** |

---

### 🧬 Логика обнаружения

#### 1. Полный блок Ren'Py
Любой исполняемый файл рядом с папкой `renpy\`, `lib\python3*.dll` или `game\*.rpa` мгновенно уничтожается. Это **осознанное политическое решение**: мы принимаем ложные срабатывания на легитимные новеллы, чтобы гарантировать нулевую выживаемость загрузчиков Amatera.

```cpp
// Хард-блок по сигнатуре — хэш не нужен
static bool isRenPyExecutable(const std::string& fullPath) {
    if (PathFileExistsA((dir + "\\renpy").c_str())) return true;
    // lib\python3*.dll отпечаток
    // game\*.rpa / *.rpyc архивы
    return false;
}
```

#### 2. Эвристики LOLBin
MSBuild или `forfiles.exe`, запущенные из `\Temp\`, `\Downloads\` или `\AppData\` с подозрительными аргументами, вызывают мгновенное завершение.

```cpp
// Цель: RenPy Loader -> forfiles -> MSBuild -> троянизированный .NET
static bool looksLikeMsBuildAbuse(const std::string& image, const std::string& cmdLine) {
    bool isMsBuild = img.find("\\msbuild.exe") != std::string::npos;
    bool isForfiles = img.find("\\forfiles.exe") != std::string::npos;
    bool fromUntrustedLoc =
        c.find("\\temp\\") != std::string::npos ||
        c.find("\\downloads\\") != std::string::npos;
    if (isMsBuild && fromUntrustedLoc) return true;
    return false;
}
```

#### 3. Рекурсивное убийство дерева процессов
Вредоносные цепочки порождают несколько поколений. Убийство только PID оставляет дочерние процессы.

```cpp
// Рекурсивно завершаем всех потомков (дети, внуки...)
static void killProcessTreeRecursive(DWORD parentPid, int depth = 0) {
    if (depth > 8) return;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // ... перечисляем детей → TerminateProcess
}
```

#### 4. Живая блокировка сети (Firewall)
До убийства процесса сбрасывается правило Windows Firewall, блокирующее **весь** трафик для этого бинарника. Даже перезапуск не поможет связаться с C2.

```cpp
// Гонка против эксфильтрации
static void blockNetworkForImage(const std::string& fullPath) {
    std::string ruleName = "FolderGuard_Block_" + baseName(fullPath);
    // netsh advfirewall firewall add rule ...
}
```

#### 5. Зачистка реестра
Каждые 10 минут сканируем `HKCU\...\Run`, `HKLM\...\Run` и WOW6432Node. Нашли? Удаляем значение, файл в карантин.

---

### 📁 Обязательная структура директорий

```
C:\ProgramData\FolderGuard\
├── watchdog.log          # Поток событий в реальном времени
├── Quarantine\           # Убитые бинарники (.quarantined)
├── hashes.txt            # SHA256-блэклист (горячая перезагрузка каждые 5 мин)
└── data.bin              # Кэш сканирования (отпечаток mtime+size)
```

> ⚠️ **Автосоздание при первом запуске. Требуется Администратор.**

---

### 🧪 Что произойдёт, если запустить малварь?

С активным FolderGuard:

1. Фейковый `Setup.exe` → **Sysmon Event 1** → `isRenPyExecutable()` true → **KILL + QUARANTINE** за миллисекунды.
2. Загрузчик через `forfiles` → **эвристика LOLBin** → та же участь.
3. `MSBuild` компилирует троянизированный `.csproj` из Downloads → **триггер MSBuild abuse** → дерево убито, правило файрвола добавлено.
4. DLL-sideload (Event 7) из Temp → **мгновенное завершение**.
5. Доступ к LSASS (Event 10) → **мертв по прибытии**.
6. Подмена процесса (Event 25) → **перехвачено и убито**.

**Результат:** ваши браузерные хранилища, Discord-токены, Telegram-сессии и криптокошельки никогда не покинут машину.

---

### 🚀 Дорожная карта

| Версия | Возможности |
|--------|-------------|
| **v0.1 (Текущая)** | Live Sysmon hook, полный блок Ren'Py, эвристики LOLBin, рекурсивное убийство дерева, файрвол, зачистка реестра, Quick Scan, Full Disk Scan |
| **v0.2** | YARA-сканирование памяти, детекция inline-hooks, интеграция AMSI |
| **v0.3** | Драйвер callback ядра (minifilter) для блокировки на уровне ФС до исполнения |
| **v1.0** | EDR-класс телеметрия, дашборд threat-hunting, движок Sigma-правил |

---

<div id="arabic"></div>

<div dir="rtl">

## 🇸🇦 العربية

### ⚔️ ما هو FolderGuard؟

**FolderGuard Ultimate** هو أداة دفاعية تعمل في الوقت الفعلي بمساعدة النواة، بُنيت لتفكيك سلسلة العدوى **Fake Game → RenPy Loader → MSBuild → Amatera Stealer** قبل أن تلمس بيانات اعتمادك.

تتصل بـ **Sysmon Event IDs 1, 3, 7, 8, 10, 11, 13, 25** وتقتل التهديد في **المراحل 1–4** — قبل فترة طويلة من تسريب السارق لحساباتك.

> 🚧 **المرحلة: ألفا مبكرة** — قيد التطوير النشط. يزداد قوةً مع كل تحديث.

---

### 🎯 سلسلة الهجوم (ما نقتله)

| المرحلة | المكون | ما يحدث | رد FolderGuard |
|---------|--------|---------|----------------|
| 1 | **تنزيل مزيف** | المستخدم ينزل "لعبة" أو "كراك" | مراقبة مجلدات التنزيل |
| 2 | **Setup.exe** | يسقط محمل RenPy متنكراً | **الحظر الشامل لـ Ren'Py** |
| 3 | **محمل RenPy** | يستخدم `forfiles.exe` للتنفيذ بالوكالة | **استدلال LOLBin** |
| 4 | **MSBuild + EtherHiding** | مشروع .NET مُطروق يُجمَّع على الفور | **كشف MSBuild abuse** |
| 5 | **Amatera Stealer** | حقن .NET في الذاكرة يجمع المتصفحات والمحافظ | **مقتول قبل التنفيذ** |
| 6 | **الحسابات في خطر** | كل شيء يرفع لـ C2 | **لا يحدث** |

---

### 🧬 منطق الكشف الأساسي

#### 1. الحظر الشامل لـ Ren'Py
أي ملف قابل للتنفيذ بجانب مجلد `renpy\`، أو `lib\python3*.dll`، أو `game\*.rpa` يُقتل فوراً. هذا **قرار سياسي مقصود**: نقبل الإيجابيات الكاذبة على الروايات الشرعية لضمان عدم بقاء أي محمل Amatera.

```cpp
// حظر صلب بالتوقيع — لا حاجة للهاش
static bool isRenPyExecutable(const std::string& fullPath) {
    if (PathFileExistsA((dir + "\\renpy").c_str())) return true;
    // lib\python3*.dll بصمة
    // game\*.rpa / *.rpyc أرشيفات
    return false;
}
```

#### 2. استدلالات سوء استخدام LOLBin
MSBuild أو `forfiles.exe` يعملان من `\Temp\` أو `\Downloads\` أو `\AppData\` مع أوامر مشبوهة يؤديان إلى الإنهاء الفوري.

```cpp
// الهدف: RenPy Loader -> forfiles -> MSBuild -> .NET مُطروق
static bool looksLikeMsBuildAbuse(const std::string& image, const std::string& cmdLine) {
    bool isMsBuild = img.find("\\msbuild.exe") != std::string::npos;
    bool isForfiles = img.find("\\forfiles.exe") != std::string::npos;
    bool fromUntrustedLoc =
        c.find("\\temp\\") != std::string::npos ||
        c.find("\\downloads\\") != std::string::npos;
    if (isMsBuild && fromUntrustedLoc) return true;
    return false;
}
```

#### 3. القتل المتكرر لشجرة العمليات
السلاسل الخبيثة تُنشئ أجيالاً متعددة. قتل PID وحده يترك الأبناء على قيد الحياة.

```cpp
// إنهاء جميع الأحفاد بشكل متكرر (أبناء، أحفاد...)
static void killProcessTreeRecursive(DWORD parentPid, int depth = 0) {
    if (depth > 8) return;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // ... تعداد الأبناء → TerminateProcess
}
```

#### 4. قطع الشبكة المباشر (Firewall)
قبل موت العملية، يتم إسقاط قاعدة Windows Firewall لحظر **كل** حركة المرور لهذا الثنائي. حتى إعادة التشغيل لا تساعد في الاتصال بـ C2.

```cpp
// سباق ضد التسريب
static void blockNetworkForImage(const std::string& fullPath) {
    std::string ruleName = "FolderGuard_Block_" + baseName(fullPath);
    // netsh advfirewall firewall add rule ...
}
```

#### 5. كسح registry للاستمرارية
كل 10 دقائق نفحص `HKCU\...\Run` و`HKLM\...\Run` وWOW6432Node. وجدنا؟ حذف القيمة، عزل الملف.

---

### 📁 هيكل الدليل المطلوب

```
C:\ProgramData\FolderGuard\
├── watchdog.log          # دفق الأحداث المباشر
├── Quarantine\           # الثنائيات المقتولة (.quarantined)
├── hashes.txt            # قائمة حظر SHA256 (إعادة تحميل ساخنة كل 5 دقائق)
└── data.bin              # ذاكرة التخزين المؤقت (بصمة mtime+size)
```

> ⚠️ **الإنشاء التلقائي عند أول تشغيل. يتطلب صلاحيات المسؤول.**

---

### 🧪 ماذا يحدث إذا شغّلت البرمجية الخبيثة؟

مع FolderGuard **في وضع الحماية**:

1. `Setup.exe` المزيف ينطلق → **Sysmon Event 1** → `isRenPyExecutable()` يرجع `true` → **KILL + QUARANTINE** خلال ملي ثانية.
2. المحمل يتوسط عبر `forfiles` → **الاستدلال اللولبيني** → نفس المصير.
3. `MSBuild` يُجمِّع `.csproj` مُطروق من Downloads → **مُحفز MSBuild abuse** → الشجرة مُقتولة، قاعدة جدار الحماية مُضافة.
4. DLL-sideload (Event 7) من Temp → **إنهاء فوري**.
5. الوصول إلى LSASS (Event 10) → **ميت عند الوصول**.
6. التلاعب بالعملية (Event 25) → **مُلتقط ومقتول**.

**النتيجة:** خزائن المتصفح، رموز Discord، جلسات Telegram، ومحافظ العملات المشفرة لا تغادر الجهاز أبداً.

---

### 🚀 خارطة الطريق

| الإصدار | الميزات |
|---------|---------|
| **v0.1 (الحالي)** | Live Sysmon hook، الحظر الشامل لـ Ren'Py، استدلالات LOLBin، القتل المتكرر لشجرة العمليات، إسقاط جدار الحماية، كسح الريجستري، Quick Scan، Full Disk Scan |
| **v0.2** | مسح ذاكرة YARA، كشف inline hooks، تكامل AMSI |
| **v0.3** | برنامج تشغيل callback kernel (minifilter) للحظر على مستوى نظام الملفات قبل التنفيذ |
| **v1.0** | تليمتري على مستوى EDR، لوحة threat-hunting، محرك قواعد Sigma |

</div>

---

<div align="center">

## 💀 Built for the red team, by the red team.

```
C:\ProgramData\FolderGuard\> ████████████████████████████
                          Admin Required | Sysmon Dependency
```

</div>
