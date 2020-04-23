rule DefaultShell: generic
{
    strings:
        $ = "eval(base64_decode(" nocase
    condition:
        all of them
}