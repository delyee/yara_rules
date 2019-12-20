rule RSFirewall: FalsePositive
{
    meta:
        description = "RSFirewall! 1.4.0"
        author = "delyee"
        date = "21.12.2019"
        sha256sum = "1e792d5bbb3834ee1aaef526ac0f9d28ffe7c5f9aff03b19ffbf1af76bd66911"
    strings:
        $ = "if (strpos($contents, 'eval(gzinflate(base64_decode') !== false)"
        $ = "@package RSFirewall!"
        $ = "function getJUMIVulnerable()"
    condition:
        all of them
}
