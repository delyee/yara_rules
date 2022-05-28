rule eval_rawurldecode: phpshell
{
    meta:
        description = "eval(rawurldecode('function%20_3qZp%28%24_mzX0rKv..."
        author = "delyee"
        date = "28.05.2022"
        sha256sum = ""
    strings:
        $ = "eval(rawurldecode("
    condition:
        not IsELF and (IsPHP and all of them)
}




