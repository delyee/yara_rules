rule APT_name_desription
{
    meta:
        description = "Обф. версия - реверс в evernote"
        author = "delyee"
        reference = "https://github.com/delyee/yara_rules"
        date = "23.08.2019"
        sha256sum = "" // sha256sum shell.php
        example = "<? $GLOBALS['_300318162_']=Array(base64_decode('ZXJyb' .'3Jfc' .'m' .'Vwb3J0aW5n'),base64_decode('c' .'2V0X' .'3' .'RpbWVfb' .'GltaXQ' .'='),base64_decode('bWQ' .'1')); ?>"
    strings:
        $php = /^\<\?/
        $globals_array = /\$\[[0_]+\]\=Array\(/ nocase ascii
        $globals = "$GLOBALS[" nocase ascii
        $base64decode = "base64_decode(" nocase ascii
    condition:
        //($php and $globals_array) or (#globals < 2 and #base64decode < 5)
        all of them
}
