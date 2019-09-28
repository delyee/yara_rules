/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           тоже самое что "any of them"
*/

rule APT_fack_LogsAnalysis
{
    meta:
        author = "delyee"
        reference = "" // url to github or blog post
        date = "06.08.2019"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""
    condition:
        $s1 and $s2 or $s3 // all of them
}

rule php_shell_names
{
    meta:
        description = "Все уникальные и пригодные для поиска имена 'fuck' шелла по результатам grep на logs13 за весь 2019 год"
        author = "delyee"
        date = "07.08.2019"
        // usage:
        // uweb -> sudo find -type f /home/ > ~/files.list && yara -s apt_fack_shell_names.yar ~/files.list
    strings:
        $ = "got.php"             //3091289
        $ = "TBJUIDez5B.php"      //584833
        $ = "wp_sib99.php"        //284244
        $ = "aWbRbbjTpP.php"      //176724
        $ = "sys_cc2.php"         //142763
        $ = "obfuscated.php"      //36310
        $ = "ASdWcxzsQ.php"       //32917
        $ = "bd1cORicQq.php"      //25991
        $ = "8KholvkKRf.php"      //17491
        $ = "BOkeqx1dJ6.php"      //13620
        $ = "5cf15710e3fa3.php"   //3468
        $ = "wp_from81.php"       //3388
        $ = "oHhMFONuMp.php"      //2887
        $ = "5cf1566c66982.php"   //2528
        $ = "5cf1563e21beb.php"   //1616
        $ = "ob2.php"             //1466
        $ = "geter.php"           //1429
        $ = "5cf156288b24c.php"   //1333
        $ = "5cf1560685927.php"   //695
}
