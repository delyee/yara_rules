private rule APT_fack_shell_v2_generic
{
    meta:
        description = "Неизвестная версия APT_fack_shell_v2"
        author = "delyee"
        reference = "https://github.com/delyee/yara_rules"
        date = "23.08.2019"
    strings:
        $globals_array = /\$GLOBALS\[\'[\w]{5,}\'\]\=Array\(/
        $globals = "$GLOBALS["
        $base64decode = "base64_decode("
    condition:
        all of them

}

rule APT_fack_shell_v2: indoxploit phpshell
{
    meta:
        description = "Обфусцированный вариант - реверс в evernote"
        author = "delyee"
        reference = "https://github.com/delyee/yara_rules"
        date = "23.08.2019"
        sha256sum = "" // sha256sum shell.php
        example = "<? $GLOBALS['_300318162_']=Array(base64_decode('ZXJyb' .'3Jfc' .'m' .'Vwb3J0aW5n'),base64_decode('c' .'2V0X' .'3' .'RpbWVfb' .'GltaXQ' .'='),base64_decode('bWQ' .'1')); ?>"
    strings:
        $globals_array = /\$GLOBALS\[\'[\w]{5,}\'\]\=Array\(/ ascii
        $globals = "$GLOBALS[" nocase ascii
        $base64decode = "base64_decode(" nocase ascii
    condition:
        ($globals_array and #globals == 4 and #base64decode == 6) or APT_fack_shell_v2_generic

}
