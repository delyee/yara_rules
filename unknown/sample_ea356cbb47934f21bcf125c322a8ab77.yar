rule sample_ea356cbb47934f21bcf125c322a8ab77: tr inj Oneindex
{
    meta:
        description = ""
        author = "delyee"
        date = "14.12.2019"
        sha256sum = "8544a24ef46c96a141725f19a8fe2500889d142591a8e3b1bf6fa3d9ac2b648c"
    strings:
        $ = "base64_decode(\"aHR0cDovLw==\")"
        $ = "$name= substr($url1 ,strrpos($url1 ,'/')"
        $ = "$url1 = $_SERVER['PHP_SELF']"
        $ = "chmod($name,0444);"
    condition:
        all of them
}
