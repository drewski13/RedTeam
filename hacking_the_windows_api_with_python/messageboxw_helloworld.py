import ctypes

user_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("Kernel32.dll")
#test
'''
int MessageBoxW(
  [in, optional] HWND    hWnd,
  [in, optional] LPCWSTR lpText,
  [in, optional] LPCWSTR lpCaption,
  [in]           UINT    uType
);
'''

hwnd = None
lpText = "Hello, World!"
lpCaption = "Hello World Caption"
uType = 0x00000001

int_ret = user_handle.MessageBoxW(hwnd, lpText, lpCaption, uType)

error = k_handle.GetLastError()
if error != 0:
    print(f"Error Code: {error}")
    exit(1)
else:
    print(f"No Errors occurred!")
    exit(0)
