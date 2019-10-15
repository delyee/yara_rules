rule Nulled_HISTFILE: malicious ioc
{
    meta:
        description = ""
        author = "delyee"
        date = "14.10.2019"
        sha256sum = "43169f4e1af2f388209f24961175d34cd3ec6e21803270d91a3b001d134e211d"
    strings:
        $ = "export"
        $ = "HISTFILE"
        $ = "/dev/null"
    condition:
        all of them
}
