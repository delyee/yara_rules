rule Generic_Eval: phpshell malicious obfuscated
{
    meta:
        description = "Obfuscated PHP eval statements"
    strings:
        $ = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/
    condition:
        all of them
}
