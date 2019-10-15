/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           тоже самое что "any of them"
*/

rule aeb3f5bc9b094c3480ea5a0a352de346: cncrypto
{
    meta:
        description = ""
        author = "delyee"
        date = "14.10.2019"
        sha256sum = "5c072d1449119bc571682bdee5bee9c7f44e558da495692c6f555151a3e0fab1"
    strings:
        $ = "<?php $_0OO=__FILE__"
        $ = "$_OOO=5874"
        $ = "yt4FMDWNm1vtRYFSl2Tzl2sAPYctrd4tiV9jiQqAPKF"
        $ = "yQvFr2R3Xkc0cbRqg109pW9sNKy3Rka0c1vtRgEsPYHtrd4tiKpuyV8"
    condition:
        all of them
}
