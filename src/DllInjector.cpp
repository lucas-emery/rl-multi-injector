#include "DllInjector.h"
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>
//#include <tchar.h>
//#include <stdio.h>

#define BAKKESMOD_DLL L"bakkesmod.dll"
#define BAKKESMOD_KEY L"Software\\BakkesMod\\AppPath"
#define BAKKESMOD_SUBKEY L"BakkesModPath"

DWORD DllInjector::InjectDLL(DWORD processID, std::wstring path) {
    DWORD result = NOPE;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
    if (hProcess) {
        if (IsBakkesModDllInjected(hProcess) == NOPE) {
            InjectDLL(hProcess, path);
            result = IsBakkesModDllInjected(hProcess);
        } else {
            result = OK;
        }
        CloseHandle(hProcess);
    }
    return result;
}

DWORD DllInjector::InjectDLL(HANDLE hProcess, std::wstring path) {
    if (hProcess) {
        LPVOID LoadLibAddr = (LPVOID) GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
        LPVOID dereercomp = VirtualAllocEx(hProcess, NULL, path.size() * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(hProcess, dereercomp, path.c_str(), path.size() * sizeof(wchar_t), NULL);
        HANDLE asdc = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE) LoadLibAddr, dereercomp, 0, NULL);
        WaitForSingleObject(asdc, INFINITE);
        VirtualFreeEx(hProcess, dereercomp, path.size() * sizeof(wchar_t), MEM_RELEASE);
        CloseHandle(asdc);
        return OK;
    }
    return NOPE;
}

std::vector<DWORD> DllInjector::GetProcessIDs(std::wstring processName) {
    std::vector<DWORD> processIDs;
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
        return processIDs;

    Process32First(processesSnapshot, &processInfo);
    do {
        if (_wcsicmp(processName.c_str(), processInfo.szExeFile) == 0) {
            BOOL iswow64 = FALSE;
            auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processInfo.th32ProcessID);
            if (hProcess) {
                if (IsWow64Process(hProcess, &iswow64) && !iswow64) {
                    processIDs.push_back(processInfo.th32ProcessID);
                } else {
                    std::cout << "INFO: IsWow64Process failed bruv " << GetLastError() << std::endl;
                }
                CloseHandle(hProcess);
            } else {
                std::cout << "INFO: Error on OpenProcess to check bitness" << std::endl;
            }
        }
    } while (Process32Next(processesSnapshot, &processInfo));

    CloseHandle(processesSnapshot);
    return processIDs;
}

DWORD DllInjector::IsBakkesModDllInjected(HANDLE hProcess) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;

    if (hProcess) {
        // Get a list of all the modules in this process.
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                TCHAR szModName[MAX_PATH];
                // Get the full path to the module's file.
                if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                    std::wstring dllName = std::wstring(szModName);
                    if (dllName.find(BAKKESMOD_DLL) != std::string::npos) {
                        return OK;
                    }
                }
            }
        }
    }
    return NOPE;
}

std::wstring DllInjector::GetBakkesModPath() {
    HKEY hKey;
    WCHAR szBuffer[512];
    DWORD dwBufferSize = sizeof(szBuffer);
    LONG nError;

    nError = RegOpenKeyExW(HKEY_CURRENT_USER, BAKKESMOD_KEY, 0, KEY_ALL_ACCESS, &hKey);
    if (ERROR_SUCCESS == nError) {
        nError = RegQueryValueExW(hKey, BAKKESMOD_SUBKEY, 0, NULL, (LPBYTE) szBuffer, &dwBufferSize);
        RegCloseKey(hKey);
        if (ERROR_SUCCESS == nError) {
            return szBuffer;
        }
    }
    return std::wstring();
}