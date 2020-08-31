#include <iostream>
#include "DllInjector.h"

#define RL_EXE L"RocketLeague_u.exe"
#define BM_DLL_PATH "./bakkesmod/dll/bakkesmod.dll"

int main() {
    auto injector = DllInjector();
    std::cout << "Scanning processes" << std::endl;
    auto pids = injector.GetProcessIDs(RL_EXE);
    std::cout << "Found " << pids.size() << " processes" << std::endl;
    for (auto &pid : pids) {
        if (injector.InjectDLL(pid, BM_DLL_PATH) == NOPE) {
            std::cout << "ERROR: Injection failed for process " << pid << std::endl;
        }
    }
    std::cout << "Done" << std::endl;
    return 0;
}
