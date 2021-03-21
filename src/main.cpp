#include <iostream>
#include "DllInjector.h"

#define RL_EXE L"RocketLeague.exe"
#define BM_DLL_PATH L"dll/bakkesmod.dll"

int wmain(int argc, wchar_t* argv[]) {
    auto injector = DllInjector();

    auto bm_path = injector.GetBakkesModPath();
    if (bm_path.empty()) {
        std::cout << "Unable to find bakkesmod folder" << std::endl;
        return EXIT_FAILURE;
    }

    std::wstring rl_exe(RL_EXE);
    if (argc > 1) {
        rl_exe = argv[1];
        std::wcout << L"Using custom process name: " << rl_exe << std::endl;
    }

    std::cout << "Scanning processes" << std::endl;
    auto pids = injector.GetProcessIDs(rl_exe);
    std::cout << "Found " << pids.size() << " processes" << std::endl;
    for (auto &pid : pids) {
        if (injector.InjectDLL(pid, bm_path + BM_DLL_PATH) == NOPE) {
            std::cout << "ERROR: Injection failed for process " << pid << std::endl;
        }
    }
    std::cout << "Done" << std::endl;
    return EXIT_SUCCESS;
}
