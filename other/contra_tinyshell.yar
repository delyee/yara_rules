include "../is/index.yar"

rule contra_tinyshell: phpshell
{
    meta:
        description = "https://github.com/contra/TinyShell"
        author = "delyee"
        date = "09.07.2021"
        sha256sum = "bb3e8ed5200869e060cb82c405956c0ac292890e9eadc8caf6c48a9d2a0fea01"
    
    strings:
        $ = { 24 5F 3D 22 24 5F 22 2E 22 22 3B 24 5F 3D 28 24 5F 5B 2B 22 22 5D 7C 22 06 22 29 2E 28 24 5F 5B 2B 22 22 5D 7C 22 05 22 29 2E 28 24 5F 5B 2B 22 22 5D 5E 22 15 22 29 3B }
        
    condition:
        all of them and not IsELF
}