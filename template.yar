/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           тоже самое что "any of them"
*/

rule APT_name_desription
{
    meta:
        description = "[][][]" // [MALWARE][PHP][SHELL] or [APT][FACK][SHELL]
        author = "delyee"
        reference = "" // url to github or blog post
        date = "05.08.2019"
        sha256sum = "" // sha256sum shell.php
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""
    condition:
        $s1 and $s2 or $s3 // all of them
}
