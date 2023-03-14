rule CT_Stealc
{
    meta:
        description = "Identifies Stealc malware"
        author = "Cipher Tech Solutions"
        hashes = "0d049f764a22e16933f8c3f1704d4e50"
        reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
        mwcp = "osacce:Stealc"
	strings:
		// 0d049f764a22e16933f8c3f1704d4e50 @ 0x00403041
		$rc4_skipkey = {
            39 18       // cmp     [eax], ebx
            75 08       // jnz     short loc_40304D
            8b 45 fc    // mov     eax, [ebp+var_4]
            88 0c 10    // mov     [eax+edx], cl
            eb 0a       // jmp     short loc_403057
            8a 00       // mov     al, [eax]
            32 c1       // xor     al, cl
            8b 4d fc    // mov     ecx, [ebp+var_4]
            88 04 11    // mov     [ecx+edx], al
		}
        $str_ip = "\x09- IP: IP?" fullword
        $str_iso = "\x09- Country: ISO?" fullword
        $str_disp = "\x09- Display Resolution: " fullword
        $str_uas = "User Agents:" fullword
	condition:
		uint16be(0) == 0x4d5a and
        (
            $rc4_skipkey or
            all of ($str_*)
        )
}