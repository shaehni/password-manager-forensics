rule vault_password
{
    strings:
        $pw = { CD 25 00 00 03 00 00 00 ?? 00 00 00 [8-] CD 25 }

    condition:
        $pw
}

rule master_password
{
    strings:
        $pw = /com\.bitwarden\.vault [a-z0-9]+@[a-z0-9]+\.[a-z]{2,5} .+ -/

    condition:
        $pw
}
