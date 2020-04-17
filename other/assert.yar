rule assert_phpshell: phpshell
{
    meta:
        author = "delyee"
        date = "17.04.2020"
        sha256sum = "d87cf273efe72a2c59422ee945265e52480e18c34a6ca7063c00322f61c7f03b"
    strings:
        $ = { 61 73 73 65 72 74 28 73 74 72 69 70 73 6c 61 73 68 65 73 28 24 5f [3-10] 5b [2-15] 5d 29 29 3b }
    condition:
        all of them
}
