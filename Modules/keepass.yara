rule vault_password
{
    strings:
        $pw = { 00 A0 57 ?? ?? ?? 7F 00 00 ?? 00 00 00 00 00 00 00 [8-] 00 00 }

    condition:
        $pw
}

rule master_password
{
    strings:
        $pw = { 5E DF 27 D1 00 3B 00 94 [16-80] 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $pw
}