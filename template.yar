/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           тоже самое что "any of them"
*/

rule `python3 -c 'print(__import__("uuid").uuid4().hex)'`
{
    meta:
        description = ""
        author = "delyee"
        date = "05.08.2019"
        sha256sum = "" // sha256sum shell.php
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""
    condition:
        $s1 and $s2 or $s3 // all of them
}
