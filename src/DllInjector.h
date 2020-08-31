#pragma once

#include <string>
#include <vector>
#include <windows.h>

enum DllInjectionResult
{
    NOPE = 0,
    OK = 1,
    NOT_RUNNING = 2
};

class DllInjector {
public:
    std::vector<DWORD> GetProcessIDs(std::wstring processName);
    DWORD InjectDLL(DWORD processID, std::string path);
private:
    DWORD IsBakkesModDllInjected(HANDLE hProcess);
    DWORD InjectDLL(HANDLE hProcess, std::string path);
};
