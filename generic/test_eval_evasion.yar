// eval/*t885*/(
// eval/*b01e589*/(
// eval/* = 65 76 61 6c 2f 2a
// */( = 2a 2f 28

rule test_eval_evasion: test
{
    meta:
        description = "видел такое при разборе кода"
        author = "delyee"
        date = "14.12.2019"
    strings:
        //$str = "eval/**/" nocase
        $hex = { 65 76 61 6c 2f 2a [0-20] 2a 2f 28 }
    condition:
        $hex
}
