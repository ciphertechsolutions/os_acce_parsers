import "pe"

rule CT_Meduza_Stealer
{
    meta:
        description = "Identifies Meduza Stealer"
        author = "Cipher Tech Solutions"
        hashes = "4c213248be08249f75b68d85dcdf3365, 6e664a49425103c5c6439deed5ed14b0"
        references = "https://russianpanda.com/2023/06/28/Meduza-Stealer-or-The-Return-of-The-Infamous-Aurora-Stealer/"
        mwcp = "osacce:Meduza"
    strings:
        $str_path = "current_path()" fullword
        $str_format = "%d-%m-%Y, %H:%M:%S" fullword
        $str_utc = "[UTC" fullword
        $str_user = "user_name" fullword
        $str_comp = "computer_name" fullword
        $str_cannot = "cannot use at() with " fullword
    condition:
        uint16be(0) == 0x4d5a and
        (
            4 of them or
            (
                pe.rich_signature.version(29395, 263) and
                pe.rich_signature.version(29395, 262) and
                pe.rich_signature.version(29395, 261) and
                (
                    pe.rich_signature.version(31935, 261) or
                    pe.rich_signature.version(32420, 261)
                ) and
                pe.rich_signature.version(29395, 260) and
                (
                    pe.rich_signature.version(31935, 260) or
                    pe.rich_signature.version(32420, 260)
                ) and
                pe.rich_signature.version(29395, 259) and
                (
                    pe.rich_signature.version(31935, 259) or
                    pe.rich_signature.version(32420, 259)
                ) and
                pe.rich_signature.version(29395, 257)
            )
        )
}