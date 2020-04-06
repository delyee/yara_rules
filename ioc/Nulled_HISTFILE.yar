rule HISTFILE: ioc
{
    meta:
        author = "delyee"
        date = "14.10.2019"
    strings:
        $ = "export HISTFILE"
        $ = "/dev/null"
    condition:
        all of them
}
