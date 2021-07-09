rule Nulled_HISTFILE: ioc
{
    meta:
        author = "delyee"
        date = "14.10.2019"
    strings:
        $ = { 65 78 70 6F 72 74 20 48 49 53 54 46 49 4C 45 3D 2F 64 65 76 2F 6E 75 6C 6C }
        $ = { 75 6E 73 65 74 20 48 49 53 54 46 49 4C 45" }
    condition:
        any of them
}
