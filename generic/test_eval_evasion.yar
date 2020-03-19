rule test_eval_evasion: test
{
    meta:
        description = "видел такое при разборе кода"
        author = "delyee"
        date = "14.12.2019"
    strings:
        $ = "eval/**/" nocase
    condition:
        all of them
}
