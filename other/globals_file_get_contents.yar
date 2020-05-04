include "../Encoders/hex.yar"

rule globals_file_get_contents: phpshell hex
{
    meta:
        author = "delyee"
        date = "14.10.2019"
    strings:
        $ = { 24 [6-24] 3d 22 }
        $ = { 66 69 6c 65 5f 67 65 74 5f 63 6f 6e 74 65 6e 74 73 28 24 }
    condition:
        all of them and Globals
}
