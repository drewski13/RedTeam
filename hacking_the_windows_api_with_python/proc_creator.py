# IMPORTs
import ctypes
from ctypes import wintypes as w

# GLOBALs
h_kernel32 = ctypes.WinDLL("Kernel32.dll")


# building the structure that will be filled in by CreateProcessW. it inherits the ctypes.Structure class
# by inheriting from ctypes.Structure we can pass tuples for field name / field type
'''
typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
'''


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", w.HANDLE),
        ("hThread", w.HANDLE),
        ("dwProcessId", w.DWORD),
        ("dwThreadId", w.DWORD),
    ]


'''
typedef struct _STARTUPINFOA {
  DWORD  cb;
  LPSTR  lpReserved;
  LPSTR  lpDesktop;
  LPSTR  lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;
'''


class STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ("cb", w.DWORD),
        ("lpReserved", w.LPWSTR),  # reserved and should be None at runtime
        ("lpDesktop", w.LPWSTR),
        ("lpTitle", w.LPWSTR),
        ("dwX", w.DWORD),
        ("dwY", w.DWORD),
        ("dwXSize", w.DWORD),
        ("dwYSize", w.DWORD),
        ("dwXCountChars", w.DWORD),
        ("dwYCountChars", w.DWORD),
        ("dwFillAttribute", w.DWORD),
        ("dwFlags", w.DWORD),  # STARTF_USESHOWWINDOW 0x00000001, The wShowWindow member contains additional
                               # information.
        ("wShowWindow", w.WORD),  # hidden vs. visible window (SW_HIDE 0, Hides the window and activates another
                                  # window. SW_SHOWNORMAL SW_NORMAL 1, Activates and displays a window. )
        ("cbReserved2", w.WORD),  # Reserved for use by the C Run-time; must be zero.
        ("lpReserved2", w.LPBYTE),  # Reserved for use by the C Run-time; must be NULL.
        ("hStdInput", w.HANDLE),
        ("hStdOutput", w.HANDLE),
        ("hStdError", w.HANDLE)
    ]

'''
BOOL CreateProcessW(
  [in, optional]      LPCWSTR               lpApplicationName,
  [in, out, optional] LPWSTR                lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,  # CREATE_NEW_CONSOLE 0x00000010, The new process has a new
                                                                console, instead of inheriting its parent's console 
                                                                (the default).
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCWSTR               lpCurrentDirectory,
  [in]                LPSTARTUPINFOW        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
If the function succeeds, the return value is nonzero.
If the function fails, the return value is zero. To get extended error information, call GetLastError.
Note that the function returns before the process has finished initialization. If a required DLL cannot be located or 
fails to initialize, the process is terminated. To get the termination status of a process, call GetExitCodeProcess.
DLL	Kernel32.dll
'''


# FUNCs
def create_process(application_name: str, show_window: int, cmdline: str) -> str:
    '''
    BOOL CreateProcessW(
      [in, optional]      LPCWSTR               lpApplicationName,
      [in, out, optional] LPWSTR                lpCommandLine,
      [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
      [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
      [in]                BOOL                  bInheritHandles,
      [in]                DWORD                 dwCreationFlags,
      [in, optional]      LPVOID                lpEnvironment,
      [in, optional]      LPCWSTR               lpCurrentDirectory,
      [in]                LPSTARTUPINFOW        lpStartupInfo,
      [out]               LPPROCESS_INFORMATION lpProcessInformation
    );
    '''
    if show_window > 0:
        print(f"[+] Starting {application_name} with VISIBLE window")
    else:
        print(f"[+] Starting {application_name} with HIDDEN window")
    lpApplicationName = application_name

    # set lpCommandLine to None (NULL) if user sent empty string
    if len(cmdline) > 1:
        lpCommandLine = f"{application_name} {cmdline}"
    else:
        lpCommandLine = None
    lpProcessAttributes = None
    lpThreadAttributes = None
    lpEnvironment = None
    lpCurrentDirectory = None
    dwCreationFlags = 0x00000010
    bInheritHandles = False
    lpProcessInformation = PROCESS_INFORMATION()

    # setting field values for startupinfo() structure
    lpStartupInfo = STARTUPINFOA()
    lpStartupInfo.wShowWindow = show_window
    lpStartupInfo.dwFlags = 0x1
    lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)

    response = h_kernel32.CreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        ctypes.byref(lpStartupInfo),
        ctypes.byref(lpProcessInformation)
    )
    print(f"\t - the new process PID is {lpProcessInformation.dwProcessId}")
    if response <= 0:
        find_last_error("Create_process")
    return f"[+] The application '{application_name}' was created successfully!"


# function to return the last error if needed when looking at WinAPI return values
def find_last_error(func_name: str):
    error = h_kernel32.GetLastError()
    if error != 0:
        print(f"{func_name} had an error. Error Code: {error}")
        exit(1)
    else:
        print(f"[+] Last Error check from {func_name} found no ERRORs!")


# MAIN
def main():
    proc_name = input("What process would you like to start? Enter full path:\n")
    cmdline = input("What cmdline would you like to pass to the new process?\n")
    show_window = input("Would you like the window to be hidden? Enter 0 to hide or 1 to show:\n")
    create_process(proc_name.strip(), int(show_window, 16), cmdline)


if __name__ == "__main__":
    main()
