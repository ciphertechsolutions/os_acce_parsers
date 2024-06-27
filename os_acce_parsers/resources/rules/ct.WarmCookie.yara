rule CT_WarmCookie_Backdoor
{
    meta:
        description = "Identifies WarmCookie backdoor"
        author = "Cipher Tech Solutions"
        hashes = "1b7f494c383385d9f76d17e5a9d757d3, 0d7f58cb43f59d78fdb10627835e5977, 1b7b6fb1a99996587a3c20ee9c390a9c, 3f22ddf4ebe3658be71a7a9fc93febae, 12aa84e2e56ae684d211679072695906"
        reference = "https://www.elastic.co/security-labs/dipping-into-danger, https://www.gdatasoftware.com/blog/2024/06/37947-badspace-backdoor, https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-resident-campaign"
        other_names = "Quickbind, BadSpace"
        mwcp = "osacce:WarmCookie"
    strings:
        // 1b7b6fb1a99996587a3c20ee9c390a9c @ 0x1800063e9
        // 3f22ddf4ebe3658be71a7a9fc93febae @ 0x180005eb7
        $decrypt_string_a = {
            // All iterations of argument loading
            (

                8b ?? 04        // mov     ebp, [rcx+4]
                48 8d ?? 08     // lea     rdi, [rcx+8]
                8b ??           // mov     esi, [rcx]
                |
                8b ?? 04        // mov     ebp, [rcx+4]
                8b ??           // mov     esi, [rcx]
                48 8d ?? 08     // lea     rdi, [rcx+8]
                |
                8b ??           // mov     esi, [rcx]
                [0-1] 8b ?? 04  // mov     ebp, [rcx+4]
                48 8d ?? 08     // lea     rdi, [rcx+8]
                |
                8b ??           // mov     esi, [rcx]
                48 8d ?? 08     // lea     rdi, [rcx+8]
                [0-1] 8b ?? 04  // mov     ebp, [rcx+4]
                |
                48 8d ?? 08     // lea     rdi, [rcx+8]
                8b ??           // mov     esi, [rcx]
                [0-1] 8b ?? 04  // mov     ebp, [rcx+4]
                |
                48 8d ?? 08     // lea     rdi, [rcx+8]
                [0-1] 8b ?? 04  // mov     ebp, [rcx+4]
                8b ??           // mov     esi, [rcx]
            )
            [0-6]
            89 ?? 24 ??         // mov     [rsp+158h+var_138], ebp
            [0-6]
            4? 8d 4? 0?         // lea     rcx, [rsi+9]; a1
            [5-16]
            4? 8? c?            // mov     r9, rax
            48 85 c0            // test    rax, rax
        }
        // 12aa84e2e56ae684d211679072695906 @ 0x180007087
        // 0d7f58cb43f59d78fdb10627835e5977 @ 0x2eda37d92
        $decrypt_string_b = {
            48 8b 8? [4-5]                      // mov     rax, [rsp+168h+arg_0]
            8b 00                               // mov     eax, [rax]
            89 ( 44 24 ?? | 85 ?? ?? ?? ?? )    // mov     [rsp+168h+var_148], eax
            48 8b 8? [4-5]                      // mov     rax, [rsp+168h+arg_0]
            8b 40 04                            // mov     eax, [rax+4]
            89 ( 44 24 ?? | 85 ?? ?? ?? ?? )    // mov     [rsp+168h+var_138], eax
            48 8b 8? [4-5]                      // mov     rax, [rsp+168h+arg_0]
            48 83 c0 08                         // add     rax, 8
            48 89 ( 44 24 ?? | 85 ?? ?? ?? ?? ) // mov     [rsp+168h+var_130], rax
            8b ( 44 24 ?? | 85 ?? ?? ?? ?? )    // mov     eax, [rsp+168h+var_148]
            48 83 c0 0?                         // add     rax, 9
            48 8? c?                            // mov     rcx, rax
            e8 [4]                              // call    sub_180005D60
            48 89 ( 44 24 ?? | 85 ?? ?? ?? ?? ) // mov     [rsp+168h+var_140], rax
            48 83 [3-5] 00                      // cmp     [rsp+168h+var_140], 0
        }
        // 1b7f494c383385d9f76d17e5a9d757d3 @ 0x2eda35dce
        $decrypt_string_c = {
            (
                8b ??           // mov     esi, [rcx]
                [0-1] 8b ?? 04  // mov     eax, [rcx+4]
                |
                8b ?? 04        // mov     eax, [rcx+4]
                8b ??           // mov     esi, [rcx]
            )
            [0-6]
            4? 8d 4? 0?         // lea     rcx, [rsi+9]
            89 ?? 24            // mov     [rsp+168h+var_13C], eax
            [6-17]
            4? 8? c?            // mov     r12, rax
            48 85 c0            // test    rax, rax
        }
        // 1b7b6fb1a99996587a3c20ee9c390a9c @ 0x1800019b1
        // 12aa84e2e56ae684d211679072695906 @ 0x1800019d9
        // 3f22ddf4ebe3658be71a7a9fc93febae @ 0x180001a1c
        $anti_analysis_compares_a = {
            e8 [4]          // call    GetAppDataFileCount
            83 f8 05        // cmp     eax, 5
            7? ??           // jge     short loc_1800019C5
            e8 [4]          // call    GetInstalledApplicationCount
            83 f8 05        // cmp     eax, 5
            7? ??           // jl      short loc_1800019F9
            e8 [4]          // call    GetNumberProcessors
            83 f8 04        // cmp     eax, 4
            7? ??           // jb      short loc_1800019DB
            e8 [4]          // call    GetMemorySize
            3d 00 0f 00 00  // cmp     eax, 0F00h
        }
        // 1b7f494c383385d9f76d17e5a9d757d3 @ 0x2eda31c79
        // 0d7f58cb43f59d78fdb10627835e5977 @ 0x2eda320a9
        $anti_analysis_compares_b = {
            e8 [4]          // call    GetTempFileCount
            83 f8 0e        // cmp     eax, 0Eh
            7? ??           // jg      short loc_2EDA31C8D
            e8 [4]          // call    GetAppDataFileCount
            83 f8 04        // cmp     eax, 4
            7? ??           // jle     short loc_2EDA31CD8
            [0-10]
            e8 [4]          // call    GetNumberProcessors
            83 f8 03        // cmp     eax, 3
            7? ??           // jbe     short loc_2EDA31CA3
            e8 [4]          // call    GetMemorySize
            3d ff 0e 00 00  // cmp     eax, 0EFFh
        }
    condition:
        uint16be(0) == 0x4d5a and
        any of them
}