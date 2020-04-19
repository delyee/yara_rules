rule PHPLockit: Encoders obfuscated
{
    meta:
        description = "Obfuscation with PHPLockit"
        author = "delyee"
        date = "29.09.2019"
    strings:
        $t_file = /\$[0O]{9}\=__FILE__/
        $t_line = /\$[0O]{9}\=__LINE__/
        $t_b64decode = "base64_decode("
        $t_urldecode = "urldecode("
        $s_eval = "eval("
    condition:
        ($t_file or $t_line) and ($t_b64decode or $t_urldecode) and $s_eval
}
