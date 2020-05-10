// eval/*t885*/(
// eval/*b01e589*/(
// eval/* = 65 76 61 6c 2f 2a
// */( = 2a 2f 28

rule eval_evasion: malicious phpshell
{
    meta:
        description = "видел такое при разборе кода"
        author = "delyee"
        date = "14.12.2019"
    strings:
        $hex = { 65 76 61 6c 2f 2a [0-50] 2a 2f 28 }
    condition:
        $hex
}
