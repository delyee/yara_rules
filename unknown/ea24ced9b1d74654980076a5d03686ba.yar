rule ea24ced9b1d74654980076a5d03686ba: phpshell
{
    meta:
        description = "unknown sample cb889342-0ca7-4a14-809f-6c44514f8d7c"
        author = "delyee"
        date = "04.10.2019"
        sha256sum = "5361bdbd75b368e79d17a47282f0ce6cd2759ccfdef8833ff38fe2a5dee95170"
    strings:
        $ = "@unserialize(sh_decrypt(@base64_decode("
        $ = "function sh_decrypt_phase($data,$key)"
        $ = "function sh_decrypt($data,$key)"
    condition:
        all of them
}
