rule n318a65_POST: phpshell
{
    meta:
        description = ""
        author = "delyee"
        date = "14.10.2019"
        sha256sum = "7d2b45efa74a473453983fab74ccad8e3efccc9781f8a0607eb7342e72ed248b"
    strings:
        $ = "eval(base64_decode($_POST['n318a65']))"
    condition:
        all of them
}
