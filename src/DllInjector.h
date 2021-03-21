#pragma once

#include <string>
#include <vector>
#include <windows.h>

enum DllInjectionResult
{
    NOPE = 0,
    OK = 1
};

class DllInjector {
public:
    std::vector<DWORD> GetProcessIDs(std::wstring processName);
    DWORD InjectDLL(DWORD processID, std::wstring path);
    std::wstring GetBakkesModPath();
private:
    DWORD IsBakkesModDllInjected(HANDLE hProcess);
    DWORD InjectDLL(HANDLE hProcess, std::wstring path);
};
