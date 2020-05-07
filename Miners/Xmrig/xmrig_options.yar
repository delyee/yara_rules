rule XmrigOptions: mining xmrig
{
    meta:
        description = "cli options"
        author = "delyee"
        date = "18.04.2020"
    strings:
        $s1 = "--donate-level" ascii
        $s2 = "--nicehash" ascii
        $s3 = "--algo" ascii
        $s4 = "--threads" ascii
        $s5 = "--cpu-max-threads-hint" ascii
        $default = "xmrig" ascii fullword
    condition:
        $default and 2 of ($s*)
}