import ctypes
from ctypes import wintypes as w

'''
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess, # DELETE (0x00010000L)	Required to delete the object.
  [in] BOOL  bInheritHandle, # If this value is TRUE, processes created by this process will inherit the handle. 
                Otherwise, the processes do not inherit this handle.
  [in] DWORD dwProcessId # The identifier of the local process to be opened.
);
DLL	Kernel32.dll

Return value
If the function succeeds, the return value is an open handle to the specified process.

If the function fails, the return value is NULL. To get extended error information, call GetLastError.
'''

# GLOBALS
#some initial setup
#getting handles to the DLLs used
h_kernel32 = ctypes.WinDLL("Kernel32.dll")
h_user32 = ctypes.WinDLL("User32.dll")
# PROCESS_ALL_ACCESS = (0x0080 | ...) <- find these on MSDN page
# shortcut
PROCESS_ALL_ACCESS = (0x00F000 | 0x00100000 | 0xFFF)


# FUNCs
def get_process_name_from_user() -> str:
    user_proc_name = input("what is the NAME for the process you want killed?\n")
    print(f"[+] The process '{user_proc_name}' will be terminated")
    return user_proc_name.strip()


def find_window_a(window_name: str) -> int:
    '''
    HWND FindWindowA(
      [in, optional] LPCSTR lpClassName, # set to NULL because im using the window name
      [in, optional] LPCSTR lpWindowName
    );
    If the function succeeds, the return value is a handle to the window that has the specified class name and window name.
    If the function fails, the return value is NULL. To get extended error information, call GetLastError.
    DLL	User32.dll
    '''
    print("[+] Getting handle to window based on title name")
    lpClassName = None
    # have to cast the python string to c_char_p after encoding to bytes to match the 'LPCSTR' type
    lpWindowName = ctypes.c_char_p(window_name.encode('utf-8'))
    resp = h_user32.FindWindowA(lpClassName, lpWindowName)
    if resp is None or resp == 0:
        find_last_error("find_window_a")
    else:
        print(f"\t- the handle to the window '{window_name}' is {resp}")
    return resp


def get_windows_thread_process_id(handle: int) -> int:
    '''
    DWORD GetWindowThreadProcessId(
      [in]            HWND    hWnd,
      [out, optional] LPDWORD lpdwProcessId
    );
    The return value is the identifier (PID) of the thread that created the window.
    DLL	User32.dll
    '''
    print("[+] Getting PID from window handle")
    # cast the handle int to a HWND
    hWnd = w.HWND(handle)
    # initialize an empty DWORD to be filled by the function by pointer reference
    pid = w.DWORD()
    # actual return value is the TID, must give the 2nd arg a pointer to a DWORD with ctypes.byref()
    tid = h_user32.GetWindowThreadProcessId(hWnd, ctypes.byref(pid))
    if pid.value <= 0:
        find_last_error("get_windows_thread_process_id")
    else:
        print(f"\t- the window PID is {pid.value}")
    return pid.value


def get_handle_to_open_process(proc_id: int) -> int:

    print(f"[+] Getting handle to process with pid {proc_id}")
    # global var created
    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    # convert decimal to hex string and then convert back to base 16 (hex) int
    dwProcessId = int(hex(proc_id), 16)
    response = h_kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if response <= 0:
        find_last_error("get_handle_to_open_process")
    else:
        print(f"\t- handle was created: {response}, so now its time to terminate it!")
    return response


def terminate_process(process_handle: int):
    '''
    BOOL TerminateProcess(
      [in] HANDLE hProcess,
      [in] UINT   uExitCode
    );
    If the function succeeds, the return value is nonzero.
    If the function fails, the return value is zero. To get extended error information, call GetLastError.
    DLL	Kernel32.dll
    '''
    print(f"[+] Getting ready to terminate the process with our handle: {process_handle}")
    # cast the process handle int to a HWND
    hProcess = w.HWND(process_handle)
    uExitCode = 0
    resp = h_kernel32.TerminateProcess(hProcess, uExitCode)
    if resp == 0:
        find_last_error("terminate_process")


# function to return the last error if needed when looking at WinAPI return values
def find_last_error(func_name: str):
    error = h_kernel32.GetLastError()
    if error != 0:
        print(f"{func_name} had an error. Error Code: {error}")
        exit(1)
    else:
        print(f"[+] Last Error check from {func_name} found no ERRORs!")


# wrapper function for the entire WinAPI calls to terminate a window by name/title
def kill_process(proc_name: str) -> str:
    # find_last_error("'kill_process() started'")
    window_handle = find_window_a(proc_name)
    window_owner_pid = get_windows_thread_process_id(window_handle)
    process_handle = get_handle_to_open_process(window_owner_pid)
    terminate_process(process_handle)
    return f"[*] DONE. process '{proc_name}' was successfully terminated"


# Main
def main():

    # get the PID for the process to be killed from user
    death_row_proc_name = get_process_name_from_user()
    # start chain to have the process killed. based on returned value, tell the user they were successful or not
    resp = kill_process(death_row_proc_name)
    print(resp)


if __name__ == "__main__":
    main()
