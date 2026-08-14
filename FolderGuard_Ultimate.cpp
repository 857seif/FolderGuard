#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winevt.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <commctrl.h>
#include <bcrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <fstream>
#include <sstream>
#include <ctime>
#include <regex>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <thread>
#include <filesystem>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")


#pragma comment(linker, \
    "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' "\
    "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(linker, "\"/manifestuac:level='requireAdministrator' uiAccess='false'\"")


static std::wstring logDir        = L"C:\\ProgramData\\FolderGuard";
static std::string  logFile       = "C:\\ProgramData\\FolderGuard\\watchdog.log";
static std::string  quarantineDir = "C:\\ProgramData\\FolderGuard\\Quarantine";
static std::string  hashesFile    = "C:\\ProgramData\\FolderGuard\\hashes.txt";
static std::string  scanCacheFile = "C:\\ProgramData\\FolderGuard\\data.bin";


static std::map<std::string, std::pair<ULONGLONG, ULONGLONG>> scanCache;
static std::mutex scanCacheMutex;

static std::set<std::string> hashBlocklist;          
static std::mutex logMutex;
static std::mutex killMutex;
static std::map<std::string, DWORD> recentKills;      
static const DWORD KILL_COOLDOWN_MS = 8000;           

static std::atomic<bool> gProtectionActive(false);
static EVT_HANDLE ghSub = nullptr;


#define WM_TRAYICON      (WM_APP + 1)
#define WM_APPEND_LOG    (WM_APP + 2)
#define ID_TRAY_SHOW     1001
#define ID_TRAY_TOGGLE   1002
#define ID_TRAY_EXIT     1003
#define ID_BTN_TOGGLE    2001
#define ID_BTN_EXIT      2002
#define ID_BTN_SCAN      2003
#define ID_BTN_QUICKSCAN 2004
#define ID_TIMER_RELOAD  3001
#define ID_TIMER_QUICKSCAN 3002
#define ID_TIMER_NETSCAN 3004
#define ID_TIMER_REGSCAN 3005

static HWND ghMainWnd = nullptr;
static HWND ghLogEdit = nullptr;
static HWND ghToggleBtn = nullptr;
static HWND ghStatusLabel = nullptr;
static HFONT ghFontTitle = nullptr;
static HFONT ghFontNormal = nullptr;
static HFONT ghFontBold = nullptr;
static NOTIFYICONDATAW gNid = {};
static bool gFirstMinimize = true;


enum class Col { Default, Green, Yellow, Red, Cyan, Gray, Magenta };


static std::set<std::string> allowlistNames = {
    "chrome.exe", "msedge.exe", "msedgewebview2.exe", "opera.exe", "operagx.exe",
    "brave.exe", "firefox.exe", "vivaldi.exe", "iexplore.exe", "waterfox.exe",
    "discord.exe", "discordptb.exe", "discordcanary.exe", "discorddevelopment.exe",
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
    "winlogon.exe", "wininit.exe", "smss.exe", "dwm.exe", "taskhostw.exe",
    "sihost.exe", "fontdrvhost.exe", "runtimebroker.exe", "searchindexer.exe",
    "searchhost.exe", "startmenuexperiencehost.exe", "shellhost.exe",
    "applicationframehost.exe", "systemsettings.exe", "securityhealthservice.exe",
    "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe", "securityhealthsystray.exe",
    "smartscreen.exe", "msseces.exe",
    "powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe", "dllhost.exe",
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "taskmgr.exe", "procmon.exe",
    "procmon64.exe", "procexp.exe", "procexp64.exe", "autoruns.exe", "autoruns64.exe",
    "sysmon.exe", "sysmon64.exe", "folderguard.exe", "folderguard_ultimate.exe"
};


static std::vector<std::string> trustedPathPrefixes = {
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
    "c:\\program files\\windows defender\\",
    "c:\\program files\\windows defender advanced threat protection\\",
    "c:\\program files\\microsoft security client\\",
    "c:\\program files\\google\\chrome\\",
    "c:\\program files\\microsoft\\edge\\",
    "c:\\program files (x86)\\microsoft\\edge\\",
    "c:\\program files\\mozilla firefox\\",
    "c:\\program files\\bravesoftware\\",
    "c:\\program files\\opera\\",
    "c:\\program files\\discord\\",
    "c:\\programdata\\folderguard\\"
};


static std::string timestamp() {
    time_t now = time(nullptr);
    tm t;
    localtime_s(&t, &now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &t);
    return std::string(buf);
}

static std::string toLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return s;
}

static std::string baseName(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

static std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], len);
    return w;
}


static void logMsg(const std::string& msg, Col c = Col::Default);

static bool isTrustedPath(const std::string& fullPath) {
    std::string lower = toLower(fullPath);
    for (const auto& prefix : trustedPathPrefixes) {
        if (lower.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

static bool isAllowlisted(const std::string& fullPath) {
    std::string name = toLower(baseName(fullPath));
    if (allowlistNames.count(name)) return true;
    if (isTrustedPath(fullPath)) return true;
    return false;
}


static void guiAppendLog(const std::string& line, Col c) {
    if (!ghMainWnd) return;
    auto* payload = new std::pair<std::string, Col>(line, c);
    PostMessageW(ghMainWnd, WM_APPEND_LOG, 0, (LPARAM)payload);
}

static void logMsg(const std::string& msg, Col c) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::string line = "[" + timestamp() + "] " + msg;
    std::ofstream f(logFile, std::ios::app);
    if (f.is_open()) f << line << std::endl;
    guiAppendLog(line, c);
}


static void loadHashBlocklist() {
    hashBlocklist.clear();
    std::ifstream f(hashesFile);
    if (!f.is_open()) {
        logMsg("No hashes.txt found yet (place SHA256 hashes in it any time).", Col::Yellow);
        return;
    }
    std::string line;
    int count = 0;
    while (std::getline(f, line)) {
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        size_t end = line.find_last_not_of(" \t\r\n");
        line = line.substr(start, end - start + 1);
        if (line.empty() || line[0] == '#') continue;

        std::string hash;
        for (char c : line) {
            if (isxdigit(static_cast<unsigned char>(c))) hash += static_cast<char>(tolower(c));
            else break;
        }
        if (hash.size() == 64) { hashBlocklist.insert(hash); count++; }
    }
    logMsg("Loaded " + std::to_string(count) + " SHA256 hashes from blocklist.", Col::Green);
}


static std::string extractField(const std::wstring& xml, const std::string& fieldName) {
    std::wstring wname(fieldName.begin(), fieldName.end());
    std::wregex re(L"<Data Name='" + wname + L"'>([^<]*)</Data>");
    std::wsmatch m;
    if (std::regex_search(xml, m, re) && m.size() > 1) {
        std::wstring w = m[1].str();
        return std::string(w.begin(), w.end());
    }
    return "";
}

static std::string extractSHA256(const std::string& hashesField) {
    std::string lower = toLower(hashesField);
    size_t pos = lower.find("sha256=");
    if (pos == std::string::npos) return "";
    pos += 7;
    if (pos + 64 > lower.size()) return "";
    std::string hash = lower.substr(pos, 64);
    for (char c : hash) if (!isxdigit(static_cast<unsigned char>(c))) return "";
    return hash;
}


static bool looksLikeLolbinAbuse(const std::string& cmdLine) {
    std::string c = toLower(cmdLine);
    static const std::vector<std::string> patterns = {
        "-enc ", "-encodedcommand", "-e ", "-w hidden", "-windowstyle hidden",
        "iex(", "invoke-expression", "downloadstring(", "downloadfile(",
        "certutil -urlcache", "certutil -decode", "mshta http", "mshta.exe http",
        "rundll32.exe http", "regsvr32 /i:http", "bitsadmin /transfer",
        "wscript.shell", "frombase64string"
    };
    for (const auto& p : patterns) if (c.find(p) != std::string::npos) return true;
    return false;
}


static bool looksLikeMsBuildAbuse(const std::string& image, const std::string& cmdLine) {
    std::string img = toLower(image);
    std::string c = toLower(cmdLine);

    bool isMsBuild = img.find("\\msbuild.exe") != std::string::npos;
    bool isForfiles = img.find("\\forfiles.exe") != std::string::npos;
    if (!isMsBuild && !isForfiles) return false;

    bool fromUntrustedLoc =
        c.find("\\temp\\") != std::string::npos ||
        c.find("\\appdata\\local\\temp\\") != std::string::npos ||
        c.find("\\appdata\\roaming\\") != std::string::npos ||
        c.find("\\users\\public\\") != std::string::npos ||
        c.find("\\downloads\\") != std::string::npos;


    if (isMsBuild && fromUntrustedLoc) return true;


    if (isForfiles && (c.find("/c ") != std::string::npos || c.find("/m ") != std::string::npos) && fromUntrustedLoc) return true;

    return false;
}


static bool isRenPyExecutable(const std::string& fullPath) {
    if (fullPath.empty()) return false;
    size_t pos = fullPath.find_last_of("\\/");
    if (pos == std::string::npos) return false;
    std::string dir = fullPath.substr(0, pos);


    if (PathFileExistsA((dir + "\\renpy").c_str())) return true;


    std::string libDir = dir + "\\lib";
    if (PathFileExistsA(libDir.c_str())) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((libDir + "\\*python3*.dll").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) { FindClose(h); return true; }
    }


    std::string gameDir = dir + "\\game";
    if (PathFileExistsA(gameDir.c_str())) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((gameDir + "\\*.rpa").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) { FindClose(h); return true; }
        h = FindFirstFileA((gameDir + "\\*.rpyc").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) { FindClose(h); return true; }
    }

    return false;
}


#include <tlhelp32.h>

static void killProcessTreeRecursive(DWORD parentPid, int depth = 0) {
    if (depth > 8) return; 
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    std::vector<DWORD> children;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ParentProcessID == parentPid && pe.th32ProcessID != parentPid) {
                children.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    for (DWORD childPid : children) {
        
        killProcessTreeRecursive(childPid, depth + 1);

        HANDLE hChild = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, childPid);
        if (hChild) {
            char pathBuf[MAX_PATH * 2] = {0};
            DWORD size = MAX_PATH * 2;
            std::string childPath;
            if (QueryFullProcessImageNameA(hChild, 0, pathBuf, &size)) childPath = pathBuf;

            if (isAllowlisted(childPath)) { CloseHandle(hChild); continue; }

            if (TerminateProcess(hChild, 1)) {
                logMsg("  -> also killed child PID " + std::to_string(childPid) +
                       (childPath.empty() ? "" : " [" + baseName(childPath) + "]"), Col::Red);
            }
            CloseHandle(hChild);
        }
    }
}


static void blockNetworkForImage(const std::string& fullPath) {
    if (fullPath.empty() || !PathFileExistsA(fullPath.c_str())) return;

    std::string ruleName = "FolderGuard_Block_" + baseName(fullPath);
    std::string cmdOut = "netsh advfirewall firewall add rule name=\"" + ruleName +
        "\" dir=out action=block program=\"" + fullPath + "\" enable=yes";
    std::string cmdIn = "netsh advfirewall firewall add rule name=\"" + ruleName +
        "_in\" dir=in action=block program=\"" + fullPath + "\" enable=yes";

    for (const std::string& cmd : {cmdOut, cmdIn}) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        std::vector<char> buf(cmd.begin(), cmd.end());
        buf.push_back('\0');
        if (CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    logMsg("  -> Firewall rule added blocking network for: " + fullPath, Col::Magenta);
}

static void killAndQuarantine(DWORD pid, const std::string& reason, const std::string& knownHash = "", bool forceKill = false) {
    std::lock_guard<std::mutex> lock(killMutex);

    HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        logMsg("Could not open PID " + std::to_string(pid) + " (already exited?)", Col::Gray);
        return;
    }

    char pathBuf[MAX_PATH * 2] = {0};
    DWORD size = MAX_PATH * 2;
    std::string fullPath;
    if (QueryFullProcessImageNameA(hProc, 0, pathBuf, &size)) fullPath = pathBuf;

    std::string name = toLower(baseName(fullPath));


    if (!forceKill && isAllowlisted(fullPath)) { CloseHandle(hProc); return; }

    DWORD now = GetTickCount();
    auto it = recentKills.find(name);
    if (it != recentKills.end() && (now - it->second) < KILL_COOLDOWN_MS) { CloseHandle(hProc); return; }
    recentKills[name] = now;

    BOOL killed = TerminateProcess(hProc, 1);
    CloseHandle(hProc);

    if (killed) {
        logMsg("KILLED PID " + std::to_string(pid) + " [" + name + "] | Reason: " + reason, Col::Red);
        if (!knownHash.empty()) logMsg("  Hash: " + knownHash, Col::Magenta);
        if (!fullPath.empty()) logMsg("  Path: " + fullPath, Col::Gray);
    } else {
        logMsg("FAILED to kill PID " + std::to_string(pid) + " (" + name + ")", Col::Yellow);
    }


    if (!fullPath.empty()) blockNetworkForImage(fullPath);
    killProcessTreeRecursive(pid);

    if (!fullPath.empty() && PathFileExistsA(fullPath.c_str())) {
        CreateDirectoryA(quarantineDir.c_str(), nullptr);
        std::string safeName = name;
        std::string ts = timestamp();
        for (auto& ch : ts) if (ch == ':' || ch == ' ') ch = '-';
        std::string dest = quarantineDir + "\\" + safeName + "_" + ts + ".quarantined";

        if (CopyFileA(fullPath.c_str(), dest.c_str(), FALSE)) {
            if (DeleteFileA(fullPath.c_str())) logMsg("QUARANTINED + DELETED -> " + dest, Col::Yellow);
            else logMsg("QUARANTINED (copy ok, delete failed - file locked) -> " + dest, Col::Yellow);
        } else if (MoveFileA(fullPath.c_str(), dest.c_str())) {
            logMsg("QUARANTINED (moved) -> " + dest, Col::Yellow);
        } else {
            logMsg("Could not quarantine: " + fullPath, Col::Gray);
        }
    }

    MessageBeep(MB_ICONWARNING);
    if (ghMainWnd) FlashWindow(ghMainWnd, TRUE);
}


static DWORD WINAPI subscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID, EVT_HANDLE hEvent) {
    if (action != EvtSubscribeActionDeliver) return 0;
    if (!gProtectionActive.load()) return 0; 

    DWORD bufUsed = 0, propCount = 0;
    EvtRender(nullptr, hEvent, EvtRenderEventXml, 0, nullptr, &bufUsed, &propCount);
    if (bufUsed == 0) return 0;

    std::vector<wchar_t> buf(bufUsed / sizeof(wchar_t) + 1);
    if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, bufUsed, buf.data(), &bufUsed, &propCount)) return 0;
    std::wstring xml(buf.data());

    std::wsmatch m;
    std::wregex idRe(L"<EventID>(\\d+)</EventID>");
    if (!std::regex_search(xml, m, idRe)) return 0;
    int eventId = std::stoi(m[1].str());

    switch (eventId) {

        case 1: {
            std::string image  = extractField(xml, "Image");
            std::string hashes = extractField(xml, "Hashes");
            std::string pidStr = extractField(xml, "ProcessId");
            std::string cmd    = extractField(xml, "CommandLine");


            if (!pidStr.empty() && isRenPyExecutable(image)) {
                killAndQuarantine(std::stoul(pidStr), "Ren'Py executable (blanket policy block)", "", true);
                break;
            }

            std::string sha256 = extractSHA256(hashes);
            if (!sha256.empty() && hashBlocklist.count(sha256) && !pidStr.empty()) {
                killAndQuarantine(std::stoul(pidStr), "HASH BLOCKLIST HIT (known malware)", sha256);
                break;
            }

            if (!pidStr.empty() && !isAllowlisted(image) && looksLikeLolbinAbuse(cmd)) {
                killAndQuarantine(std::stoul(pidStr),
                    "Suspicious LOLBin-style command line in " + baseName(image));
                break;
            }

            if (!pidStr.empty() && looksLikeMsBuildAbuse(image, cmd)) {
                killAndQuarantine(std::stoul(pidStr),
                    "MSBuild/forfiles abuse pattern (fake-installer loader chain) in " + baseName(image));
            }
            break;
        }


        case 8: {
            std::string srcImg = extractField(xml, "SourceImage");
            std::string tgtImg = extractField(xml, "TargetImage");
            std::string pidStr = extractField(xml, "SourceProcessId");
            if (!pidStr.empty() && !isAllowlisted(srcImg)) {
                killAndQuarantine(std::stoul(pidStr),
                    "Process Injection (CreateRemoteThread) into " + baseName(tgtImg));
            }
            break;
        }


        case 7: {
            std::string image  = extractField(xml, "Image");
            std::string loaded = extractField(xml, "ImageLoaded");
            std::string pidStr = extractField(xml, "ProcessId");
            std::string lowerLoaded = toLower(loaded);

            bool fromUntrustedLoc =
                lowerLoaded.find("\\temp\\") != std::string::npos ||
                lowerLoaded.find("\\appdata\\local\\temp\\") != std::string::npos ||
                lowerLoaded.find("\\appdata\\roaming\\") != std::string::npos ||
                lowerLoaded.find("\\users\\public\\") != std::string::npos;

            if (fromUntrustedLoc && !pidStr.empty() && !isAllowlisted(image)) {
                killAndQuarantine(std::stoul(pidStr),
                    "Suspicious DLL sideload (" + baseName(loaded) + ") into " + baseName(image));
            }
            break;
        }


        case 10: {
            std::string srcImg = extractField(xml, "SourceImage");
            std::string tgtImg = toLower(extractField(xml, "TargetImage"));
            std::string pidStr = extractField(xml, "SourceProcessId");
            std::string access = extractField(xml, "GrantedAccess");
            if (pidStr.empty()) break;

            if (tgtImg.find("lsass.exe") != std::string::npos) {
                if (!isAllowlisted(srcImg))
                    killAndQuarantine(std::stoul(pidStr), "LSASS Access (possible credential dump)");
            } else if (access == "0x1410" || access == "0x1fffff" || access == "0x1438") {
                if (!isAllowlisted(srcImg))
                    killAndQuarantine(std::stoul(pidStr),
                        "Suspicious Process Access (" + access + ") to " + baseName(tgtImg));
            }
            break;
        }


        case 11: {
            std::string pidStr = extractField(xml, "ProcessId");
            std::string target = extractField(xml, "TargetFilename");
            std::string image  = extractField(xml, "Image");
            if (pidStr.empty()) break;

            std::string lowerTarget = toLower(target);
            static const std::vector<std::string> credMarkers = {
                "\\login data", "\\local state", "\\web data", "\\cookies",
                "\\leveldb", "\\network\\cookies", "\\wallet", "\\keystore",
                "metamask", "exodus", "electrum", "\\telegram desktop\\tdata",
                "\\local extension settings\\"
            };
            bool isCredStore = false;
            for (const auto& mkr : credMarkers) {
                if (lowerTarget.find(mkr) != std::string::npos) { isCredStore = true; break; }
            }

            if (isCredStore && !isAllowlisted(image)) {
                killAndQuarantine(std::stoul(pidStr),
                    "Wrote to credential / wallet store: " + baseName(target));
            }
            break;
        }


        case 3: {
            std::string pidStr = extractField(xml, "ProcessId");
            std::string image  = extractField(xml, "Image");
            std::string ip     = extractField(xml, "DestinationIp");
            std::string port   = extractField(xml, "DestinationPort");
            if (pidStr.empty() || image.empty()) break;

            std::string lowerImg = toLower(image);
            bool fromTemp =
                lowerImg.find("\\temp\\") != std::string::npos ||
                lowerImg.find("\\appdata\\local\\temp\\") != std::string::npos ||
                lowerImg.find("\\appdata\\roaming\\") != std::string::npos;

            if (fromTemp && !isAllowlisted(image)) {
                killAndQuarantine(std::stoul(pidStr),
                    "Suspicious outbound connection from Temp/AppData to " + ip + ":" + port);
            }
            break;
        }

        
        case 13: {
            std::string image  = extractField(xml, "Image");
            std::string target = extractField(xml, "TargetObject");
            std::string pidStr = extractField(xml, "ProcessId");
            std::string lowerTarget = toLower(target);

            bool isRunKey =
                lowerTarget.find("\\currentversion\\run") != std::string::npos ||
                lowerTarget.find("\\currentversion\\runonce") != std::string::npos ||
                lowerTarget.find("shell folders") != std::string::npos;

            if (isRunKey && !pidStr.empty() && !isAllowlisted(image)) {
               
                killAndQuarantine(std::stoul(pidStr),
                    "Persistence attempt (Run key) by " + baseName(image));
            }
            break;
        }


        case 25: {
            std::string image  = extractField(xml, "Image");
            std::string pidStr = extractField(xml, "ProcessId");
            std::string type   = extractField(xml, "Type"); 
            if (!pidStr.empty() && !isAllowlisted(image)) {
                killAndQuarantine(std::stoul(pidStr),
                    "Process tampering (" + (type.empty() ? std::string("hollowing/herpaderping") : type) +
                    ") in " + baseName(image));
            }
            break;
        }
    }
    return 0;
}



static std::string sha256File(const std::wstring& path) {
    std::string result;
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return result;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        CloseHandle(hFile); return result;
    }
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0); CloseHandle(hFile); return result;
    }

    std::vector<BYTE> buf(1 << 20); 
    DWORD read = 0;
    while (ReadFile(hFile, buf.data(), (DWORD)buf.size(), &read, nullptr) && read > 0) {
        BCryptHashData(hHash, buf.data(), read, 0);
    }

    BYTE digest[32];
    if (BCryptFinishHash(hHash, digest, sizeof(digest), 0) == 0) {
        static const char* hexchars = "0123456789abcdef";
        result.reserve(64);
        for (BYTE b : digest) { result += hexchars[b >> 4]; result += hexchars[b & 0xF]; }
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    return result;
}

static std::atomic<long> gScanFilesChecked(0);
static std::atomic<long> gScanSkippedCached(0);
static std::atomic<long> gScanHits(0);


static bool getFileStamp(const std::wstring& path, ULONGLONG& mtimeOut, ULONGLONG& sizeOut) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return false;
    ULARGE_INTEGER t; t.LowPart = fad.ftLastWriteTime.dwLowDateTime; t.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    ULARGE_INTEGER s; s.LowPart = fad.nFileSizeLow; s.HighPart = fad.nFileSizeHigh;
    mtimeOut = t.QuadPart;
    sizeOut  = s.QuadPart;
    return true;
}

static void loadScanCache() {
    std::lock_guard<std::mutex> lock(scanCacheMutex);
    scanCache.clear();
    std::ifstream f(scanCacheFile);
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        size_t t1 = line.find('\t');
        if (t1 == std::string::npos) continue;
        size_t t2 = line.find('\t', t1 + 1);
        if (t2 == std::string::npos) continue;
        std::string path = line.substr(0, t1);
        ULONGLONG mtime = strtoull(line.substr(t1 + 1, t2 - t1 - 1).c_str(), nullptr, 16);
        ULONGLONG size  = strtoull(line.substr(t2 + 1).c_str(), nullptr, 16);
        scanCache[path] = { mtime, size };
    }
    logMsg("Loaded scan cache (data.bin): " + std::to_string(scanCache.size()) + " known-clean files.", Col::Gray);
}

static void saveScanCache() {
    std::lock_guard<std::mutex> lock(scanCacheMutex);
    CreateDirectoryW(logDir.c_str(), nullptr);
    std::ofstream f(scanCacheFile, std::ios::trunc);
    if (!f.is_open()) return;
    char buf[64];
    for (auto& kv : scanCache) {
        snprintf(buf, sizeof(buf), "%llx\t%llx", kv.second.first, kv.second.second);
        f << kv.first << "\t" << buf << "\n";
    }
}


static bool isCachedClean(const std::string& path, ULONGLONG mtime, ULONGLONG size) {
    std::lock_guard<std::mutex> lock(scanCacheMutex);
    auto it = scanCache.find(path);
    if (it == scanCache.end()) return false;
    return it->second.first == mtime && it->second.second == size;
}

static void markCachedClean(const std::string& path, ULONGLONG mtime, ULONGLONG size) {
    std::lock_guard<std::mutex> lock(scanCacheMutex);
    scanCache[path] = { mtime, size };
}


static void quarantineFileOnDisk(const std::wstring& wpath, const std::string& reason) {
    std::string path(wpath.begin(), wpath.end()); 
    CreateDirectoryA(quarantineDir.c_str(), nullptr);
    std::string safeName = toLower(baseName(path));
    std::string ts = timestamp();
    for (auto& ch : ts) if (ch == ':' || ch == ' ') ch = '-';
    std::string dest = quarantineDir + "\\" + safeName + "_" + ts + ".quarantined";

    if (CopyFileA(path.c_str(), dest.c_str(), FALSE)) {
        DeleteFileA(path.c_str());
        logMsg("SCAN HIT -> quarantined+deleted: " + path + " | " + reason, Col::Red);
    } else {
        logMsg("SCAN HIT but could not quarantine (locked?): " + path + " | " + reason, Col::Yellow);
    }
    gScanHits++;
}


static void scanDirectoryWorker(const std::filesystem::path& root) {
    std::error_code ec;
    std::filesystem::recursive_directory_iterator it(root,
        std::filesystem::directory_options::skip_permission_denied, ec);
    std::filesystem::recursive_directory_iterator end;

    for (; it != end; it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        if (!gProtectionActive.load()) return; // allow abort if protection is stopped mid-scan
        const auto& entry = *it;
        if (!entry.is_regular_file(ec)) continue;

        std::wstring wpath = entry.path().wstring();
        std::wstring ext = entry.path().extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

        if (ext != L".exe" && ext != L".dll" && ext != L".scr") continue;

        std::string path = toLower(std::string(wpath.begin(), wpath.end()));

        ULONGLONG mtime = 0, fsize = 0;
        bool gotStamp = getFileStamp(wpath, mtime, fsize);


        if (gotStamp && isCachedClean(path, mtime, fsize)) {
            gScanSkippedCached++;
            continue;
        }

        gScanFilesChecked++;

 
        if (isRenPyExecutable(path)) {
            quarantineFileOnDisk(wpath, "Ren'Py executable (blanket policy block)");
            continue;
        }

        bool clean = true;

        if (entry.file_size(ec) < 300ULL * 1024 * 1024) {
            std::string h = sha256File(wpath);
            if (!h.empty() && hashBlocklist.count(h)) {
                quarantineFileOnDisk(wpath, "HASH BLOCKLIST HIT (known malware): " + h);
                clean = false;
            }
        }


        if (clean && gotStamp) markCachedClean(path, mtime, fsize);
    }
}


static void runQuickScan() {
    logMsg("=== QUICK SCAN starting (Downloads/Desktop/Temp/AppData) ===", Col::Cyan);
    gScanFilesChecked = 0;
    gScanSkippedCached = 0;
    gScanHits = 0;

    std::vector<std::filesystem::path> roots;
    std::error_code ec;

    std::filesystem::path usersDir = "C:\\Users";
    if (std::filesystem::exists(usersDir, ec)) {
        for (auto& profile : std::filesystem::directory_iterator(usersDir, ec)) {
            if (ec) { ec.clear(); continue; }
            if (!profile.is_directory(ec)) continue;

            std::wstring pname = profile.path().filename().wstring();
            std::string pnameLower = toLower(std::string(pname.begin(), pname.end()));
           
            if (pnameLower == "default" || pnameLower == "public" ||
                pnameLower == "default user" || pnameLower == "all users") continue;

            static const std::vector<std::wstring> subpaths = {
                L"\\Downloads", L"\\Desktop",
                L"\\AppData\\Local\\Temp",   
                L"\\AppData\\Roaming",
                L"\\AppData\\Local"
            };
            for (auto& sub : subpaths) {
                std::filesystem::path p = profile.path().wstring() + sub;
                if (std::filesystem::exists(p, ec)) roots.push_back(p);
            }
        }
    }
   
    wchar_t sysTemp[MAX_PATH];
    if (GetTempPathW(MAX_PATH, sysTemp)) {
        std::filesystem::path p(sysTemp);
        if (std::filesystem::exists(p, ec)) roots.push_back(p);
    }

    if (roots.empty()) {
        logMsg("Quick scan found no target folders (unexpected).", Col::Yellow);
        return;
    }

    std::vector<std::thread> pool;
    const unsigned maxThreads = std::max(2u, std::thread::hardware_concurrency());
    for (auto& r : roots) {
        if (pool.size() >= maxThreads) { pool.front().join(); pool.erase(pool.begin()); }
        pool.emplace_back(scanDirectoryWorker, r);
    }
    for (auto& t : pool) t.join();
    saveScanCache();

    logMsg("=== QUICK SCAN complete. Checked: " + std::to_string(gScanFilesChecked.load()) +
           " | Skipped (cached-clean): " + std::to_string(gScanSkippedCached.load()) +
           " | Threats removed: " + std::to_string(gScanHits.load()) + " ===", Col::Green);
}

static void runFullDiskScan() {
    logMsg("=== FULL DISK SCAN starting ===", Col::Cyan);
    gScanFilesChecked = 0;
    gScanHits = 0;

    std::vector<std::filesystem::path> roots;
    DWORD drives = GetLogicalDrives();
    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        if (!(drives & (1 << (letter - 'A')))) continue;
        std::string root = std::string(1, letter) + ":\\";
        UINT type = GetDriveTypeA(root.c_str());
        if (type != DRIVE_FIXED) continue; 
        roots.push_back(root);
    }

    std::vector<std::thread> pool;
    const unsigned maxThreads = std::max(2u, std::thread::hardware_concurrency());
    for (auto& r : roots) {
        if (pool.size() >= maxThreads) { pool.front().join(); pool.erase(pool.begin()); }
        pool.emplace_back(scanDirectoryWorker, r);
    }
    for (auto& t : pool) t.join();

    logMsg("=== FULL DISK SCAN complete. Files checked: " + std::to_string(gScanFilesChecked.load()) +
           " | Threats removed: " + std::to_string(gScanHits.load()) + " ===", Col::Green);
}


static void scanNetworkConnections() {
    DWORD size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return;
    std::vector<BYTE> buf(size);
    auto* pTcpTable = (PMIB_TCPTABLE_OWNER_PID)buf.data();
    if (GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;

    for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
        if (!gProtectionActive.load()) return;
        auto& row = pTcpTable->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
        DWORD pid = row.dwOwningPid;
        if (pid == 0) continue;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) continue;
        char pathBuf[MAX_PATH * 2] = {0};
        DWORD psize = MAX_PATH * 2;
        std::string fullPath;
        if (QueryFullProcessImageNameA(hProc, 0, pathBuf, &psize)) fullPath = pathBuf;
        CloseHandle(hProc);
        if (fullPath.empty() || isAllowlisted(fullPath)) continue;

        std::string lower = toLower(fullPath);
        bool fromUntrusted =
            lower.find("\\temp\\") != std::string::npos ||
            lower.find("\\appdata\\local\\temp\\") != std::string::npos ||
            lower.find("\\appdata\\roaming\\") != std::string::npos ||
            lower.find("\\users\\public\\") != std::string::npos ||
            lower.find("\\downloads\\") != std::string::npos;
        if (!fromUntrusted) continue;

        in_addr remote; remote.S_un.S_addr = row.dwRemoteAddr;
        char ipStr[INET_ADDRSTRLEN] = {0};
        InetNtopA(AF_INET, &remote, ipStr, sizeof(ipStr));

        killAndQuarantine(pid, std::string("Ongoing network connection from untrusted location to ") + ipStr);
    }
}


static void scanRegistryPersistenceSweep() {
    struct RegLoc { HKEY root; std::wstring path; };
    std::vector<RegLoc> locs = {
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
    };

    for (auto& loc : locs) {
        if (!gProtectionActive.load()) return;
        HKEY hKey;
        if (RegOpenKeyExW(loc.root, loc.path.c_str(), 0, KEY_READ | KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) continue;

        std::vector<std::wstring> toDelete;
        DWORD idx = 0;
        while (true) {
            wchar_t valName[256]; DWORD valNameSize = 256;
            BYTE data[2048]; DWORD dataSize = sizeof(data); DWORD type = 0;

            LONG r = RegEnumValueW(hKey, idx, valName, &valNameSize, nullptr, &type, data, &dataSize);
            if (r == ERROR_NO_MORE_ITEMS) break;
            idx++;
            if (r != ERROR_SUCCESS) continue;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

            std::wstring wval(reinterpret_cast<wchar_t*>(data));
            std::string val(wval.begin(), wval.end());
            if (!val.empty() && val.front() == '"') val.erase(0, 1);
            size_t exePos = toLower(val).find(".exe");
            std::string path = (exePos != std::string::npos) ? val.substr(0, exePos + 4) : val;

            std::string lowerPath = toLower(path);
            bool untrusted =
                lowerPath.find("\\temp\\") != std::string::npos ||
                lowerPath.find("\\appdata\\local\\temp\\") != std::string::npos ||
                lowerPath.find("\\appdata\\roaming\\") != std::string::npos ||
                lowerPath.find("\\users\\public\\") != std::string::npos ||
                lowerPath.find("\\downloads\\") != std::string::npos;

            if (untrusted && !isAllowlisted(path)) {
                std::string valNameStr(valName, valName + wcslen(valName));
                logMsg("Registry sweep: removing persistence entry '" + valNameStr + "' -> " + path, Col::Red);
                toDelete.push_back(std::wstring(valName));
                if (!path.empty() && PathFileExistsA(path.c_str())) {
                    std::wstring wpath(path.begin(), path.end());
                    quarantineFileOnDisk(wpath, "Registry persistence sweep");
                }
            }
        }
        for (auto& name : toDelete) RegDeleteValueW(hKey, name.c_str());
        RegCloseKey(hKey);
    }
}

static void applyHardening() {
    logMsg("[1/3] Applying strong OS hardening...", Col::Cyan);
    std::string ps = R"(
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        $asrIds = @(
            '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
            'e6db77e5-3df2-4cf1-b95a-636979351e5b', 'd1e49aac-8f56-4280-b9ba-993a6d77406c',
            '3b576869-a4ec-4529-8536-b80a7769e899', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
            '5beb7efe-fd9a-4556-801d-275e5ffc04cc', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
            '01443614-cd74-433a-b99e-2ecdc07bfc25', '26190899-1602-49e8-8b27-eb1d0a1ce869',
            '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
        )
        foreach ($id in $asrIds) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        }
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
        Write-Output 'Hardening commands executed'
    )";

    std::string cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" + ps + "\"";
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    std::vector<char> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back('\0');

    if (CreateProcessA(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 45000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        logMsg("      Hardening applied. (Reboot recommended for LSA Protection.)", Col::Green);
    } else {
        logMsg("      Could not launch PowerShell for hardening.", Col::Yellow);
    }
}

static bool sysmonInstalled() {
    EVT_HANDLE h = EvtQuery(nullptr, L"Microsoft-Windows-Sysmon/Operational", L"*", EvtQueryChannelPath);
    if (h) { EvtClose(h); return true; }
    return false;
}


static void updateStatusUI() {
    if (!ghStatusLabel || !ghToggleBtn) return;
    if (gProtectionActive.load()) {
        SetWindowTextW(ghStatusLabel, L"● PROTECTED - LIVE");
        SetWindowTextW(ghToggleBtn, L"Stop Protection");
    } else {
        SetWindowTextW(ghStatusLabel, L"● PROTECTION STOPPED");
        SetWindowTextW(ghToggleBtn, L"Start Protection");
    }
    InvalidateRect(ghStatusLabel, nullptr, TRUE);
    if (gNid.cbSize) {
        wcscpy_s(gNid.szTip, gProtectionActive.load() ? L"FolderGuard - Protected" : L"FolderGuard - Stopped");
        Shell_NotifyIconW(NIM_MODIFY, &gNid);
    }
}

static void startProtection() {
    if (gProtectionActive.load()) return;

    if (!sysmonInstalled()) {
        MessageBoxW(ghMainWnd,
            L"Sysmon is not installed.\n\nRun install_folderguard.bat first "
            L"(as Administrator) - it installs Sysmon and its config automatically.",
            L"FolderGuard Ultimate", MB_ICONWARNING | MB_OK);
        return;
    }

    CreateDirectoryW(logDir.c_str(), nullptr);
    CreateDirectoryA(quarantineDir.c_str(), nullptr);

    static bool hardenedOnce = false;
    if (!hardenedOnce) { applyHardening(); hardenedOnce = true; }

    loadHashBlocklist();

    const wchar_t* query =
        L"*[System[(EventID=1 or EventID=3 or EventID=7 or EventID=8 or EventID=10 or EventID=11 or EventID=13 or EventID=25)]]";

    ghSub = EvtSubscribe(nullptr, nullptr, L"Microsoft-Windows-Sysmon/Operational", query,
                         nullptr, nullptr, (EVT_SUBSCRIBE_CALLBACK)subscriptionCallback,
                         EvtSubscribeToFutureEvents);

    if (!ghSub) {
        logMsg("Failed to subscribe to Sysmon events. Run as Administrator.", Col::Red);
        MessageBoxW(ghMainWnd, L"Failed to subscribe to Sysmon events.\nMake sure the app is running as Administrator.",
                    L"FolderGuard Ultimate", MB_ICONERROR | MB_OK);
        return;
    }

    gProtectionActive.store(true);
    SetTimer(ghMainWnd, ID_TIMER_RELOAD, 5 * 60 * 1000, nullptr); 
    SetTimer(ghMainWnd, ID_TIMER_QUICKSCAN, 5 * 60 * 1000, nullptr);
    SetTimer(ghMainWnd, ID_TIMER_NETSCAN, 60 * 1000, nullptr);       
    SetTimer(ghMainWnd, ID_TIMER_REGSCAN, 10 * 60 * 1000, nullptr); 
    logMsg("=== Protection ARMED - monitoring live ===", Col::Green);
    updateStatusUI();


    loadScanCache();
    std::thread(runQuickScan).detach();
    std::thread(scanNetworkConnections).detach();
    std::thread(scanRegistryPersistenceSweep).detach();
}

static void stopProtection() {
    if (!gProtectionActive.load()) return;
    gProtectionActive.store(false);
    KillTimer(ghMainWnd, ID_TIMER_RELOAD);
    KillTimer(ghMainWnd, ID_TIMER_QUICKSCAN);
    KillTimer(ghMainWnd, ID_TIMER_NETSCAN);
    KillTimer(ghMainWnd, ID_TIMER_REGSCAN);
    if (ghSub) { EvtClose(ghSub); ghSub = nullptr; }
    logMsg("=== Protection stopped by user ===", Col::Yellow);
    updateStatusUI();
}


static COLORREF colorFor(Col c) {
    switch (c) {
        case Col::Green:   return RGB(46, 204, 113);
        case Col::Yellow:  return RGB(241, 196, 15);
        case Col::Red:     return RGB(231, 76, 60);
        case Col::Cyan:    return RGB(52, 152, 219);
        case Col::Gray:    return RGB(149, 165, 166);
        case Col::Magenta: return RGB(155, 89, 182);
        default:           return RGB(220, 220, 220);
    }
}

static void appendToLogEdit(const std::string& line, Col c) {
    if (!ghLogEdit) return;
    std::wstring wline = widen(line) + L"\r\n";

    int len = GetWindowTextLengthW(ghLogEdit);
    SendMessageW(ghLogEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(ghLogEdit, EM_REPLACESEL, FALSE, (LPARAM)wline.c_str());

    
    if (len > 400000) {
        SendMessageW(ghLogEdit, EM_SETSEL, 0, (WPARAM)(len / 2));
        SendMessageW(ghLogEdit, EM_REPLACESEL, FALSE, (LPARAM)L"");
    }
    (void)c; 
}

static void addTrayIcon(HWND hwnd) {
    gNid.cbSize = sizeof(NOTIFYICONDATAW);
    gNid.hWnd = hwnd;
    gNid.uID = 1;
    gNid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    gNid.uCallbackMessage = WM_TRAYICON;
    gNid.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    wcscpy_s(gNid.szTip, L"FolderGuard - Stopped");
    Shell_NotifyIconW(NIM_ADD, &gNid);
}

static void showTrayMenu(HWND hwnd) {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, ID_TRAY_SHOW, L"Show Window");
    AppendMenuW(menu, MF_STRING, ID_TRAY_TOGGLE,
                gProtectionActive.load() ? L"Stop Protection" : L"Start Protection");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"Exit");

    POINT pt; GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
    PostMessageW(hwnd, WM_NULL, 0, 0); 
    DestroyMenu(menu);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            ghFontTitle  = CreateFontW(26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
            ghFontBold   = CreateFontW(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
            ghFontNormal = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Consolas");

            HWND title = CreateWindowW(L"STATIC", L"FolderGuard Ultimate",
                WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 15, 400, 34, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(title, WM_SETFONT, (WPARAM)ghFontTitle, TRUE);

            ghStatusLabel = CreateWindowW(L"STATIC", L"● PROTECTION STOPPED",
                WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 55, 300, 22, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(ghStatusLabel, WM_SETFONT, (WPARAM)ghFontBold, TRUE);

            ghToggleBtn = CreateWindowW(L"BUTTON", L"Start Protection",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 400, 45, 150, 36, hwnd, (HMENU)ID_BTN_TOGGLE, nullptr, nullptr);
            SendMessageW(ghToggleBtn, WM_SETFONT, (WPARAM)ghFontBold, TRUE);

            HWND scanBtn = CreateWindowW(L"BUTTON", L"Scan Full Disk",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 400, 90, 150, 30, hwnd, (HMENU)ID_BTN_SCAN, nullptr, nullptr);
            SendMessageW(scanBtn, WM_SETFONT, (WPARAM)ghFontBold, TRUE);

            HWND quickScanBtn = CreateWindowW(L"BUTTON", L"Quick Scan",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 560, 90, 100, 30, hwnd, (HMENU)ID_BTN_QUICKSCAN, nullptr, nullptr);
            SendMessageW(quickScanBtn, WM_SETFONT, (WPARAM)ghFontBold, TRUE);

            HWND exitBtn = CreateWindowW(L"BUTTON", L"Exit",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 560, 45, 100, 36, hwnd, (HMENU)ID_BTN_EXIT, nullptr, nullptr);
            SendMessageW(exitBtn, WM_SETFONT, (WPARAM)ghFontBold, TRUE);

            ghLogEdit = CreateWindowW(L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                20, 130, 640, 300, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(ghLogEdit, WM_SETFONT, (WPARAM)ghFontNormal, TRUE);

            addTrayIcon(hwnd);
            appendToLogEdit("[" + timestamp() + "] FolderGuard Ultimate GUI ready. Click 'Start Protection' to arm.", Col::Cyan);
            return 0;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_BTN_TOGGLE:
                case ID_TRAY_TOGGLE:
                    if (gProtectionActive.load()) stopProtection(); else startProtection();
                    break;
                case ID_BTN_SCAN: {
                    if (!gProtectionActive.load()) {
                        MessageBoxW(hwnd, L"Start Protection first (needed so the scan can quarantine files).",
                                    L"FolderGuard Ultimate", MB_ICONWARNING | MB_OK);
                        break;
                    }
                    std::thread(runFullDiskScan).detach();
                    break;
                }
                case ID_BTN_QUICKSCAN: {
                    if (!gProtectionActive.load()) {
                        MessageBoxW(hwnd, L"Start Protection first (needed so the scan can quarantine files).",
                                    L"FolderGuard Ultimate", MB_ICONWARNING | MB_OK);
                        break;
                    }
                    std::thread(runQuickScan).detach();
                    break;
                }
                case ID_TRAY_SHOW:
                    ShowWindow(hwnd, SW_SHOW);
                    SetForegroundWindow(hwnd);
                    break;
                case ID_TRAY_EXIT:
                case ID_BTN_EXIT:
                    DestroyWindow(hwnd);
                    break;
            }
            return 0;

        case WM_TIMER:
            if (wParam == ID_TIMER_RELOAD) loadHashBlocklist();
            if (wParam == ID_TIMER_QUICKSCAN) std::thread(runQuickScan).detach();
            if (wParam == ID_TIMER_NETSCAN) std::thread(scanNetworkConnections).detach();
            if (wParam == ID_TIMER_REGSCAN) std::thread(scanRegistryPersistenceSweep).detach();
            return 0;

        case WM_APPEND_LOG: {
            auto* payload = (std::pair<std::string, Col>*)lParam;
            appendToLogEdit(payload->first, payload->second);
            delete payload;
            return 0;
        }

        case WM_TRAYICON:
            if (lParam == WM_LBUTTONDBLCLK) {
                ShowWindow(hwnd, SW_SHOW);
                SetForegroundWindow(hwnd);
            } else if (lParam == WM_RBUTTONUP) {
                showTrayMenu(hwnd);
            }
            return 0;

        case WM_SYSCOMMAND:
            if ((wParam & 0xFFF0) == SC_MINIMIZE) {
                ShowWindow(hwnd, SW_HIDE);
                if (gFirstMinimize) {
                    gNid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
                    wcscpy_s(gNid.szInfoTitle, L"FolderGuard Ultimate");
                    wcscpy_s(gNid.szInfo, L"Still running in the tray. Protection status is unchanged.");
                    gNid.dwInfoFlags = NIIF_INFO;
                    Shell_NotifyIconW(NIM_MODIFY, &gNid);
                    gFirstMinimize = false;
                }
                return 0;
            }
            break;

        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;

        case WM_DESTROY:
            stopProtection();
            Shell_NotifyIconW(NIM_DELETE, &gNid);
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);


    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"FolderGuardUltimate_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"FolderGuard Ultimate is already running (check the system tray).",
                    L"FolderGuard Ultimate", MB_ICONINFORMATION | MB_OK);
        return 0;
    }

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"FolderGuardUltimateWndClass";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 34));
    wc.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    RegisterClassW(&wc);

    ghMainWnd = CreateWindowW(wc.lpszClassName, L"FolderGuard Ultimate",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 485, nullptr, nullptr, hInst, nullptr);

    ShowWindow(ghMainWnd, nCmdShow);
    UpdateWindow(ghMainWnd);


    startProtection();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseHandle(hMutex);
    return (int)msg.wParam;
}
