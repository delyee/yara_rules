/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           то же самое что "any of them"
*/

rule SmartStealerPHP_index: tr cnc
{
    meta:
        description = "smartStealerPHP - index.php"
        author = "delyee"
        date = "19.12.2019"
        sha256sum = "55c2a6a65b8d2fc40f5b725d8c0ab9c17bbd9f5eaf376311819cf2ddf1434a30"
    strings:
        $s1 = "elseif ($_GET[\"action\"] == \"logs\" || !isset($_GET[\"action\"]))"
        $s2 = "if ($_SESSION[\"user\"]!=$username || $_SESSION[\"ip\"]!=$_SERVER[\"REMOTE_ADDR\"])"
        $s3 = "<html><head><title>SmartStealer Log Manager"
        $s4 = "if ($_SESSION[\"order\"] == 0) $tmp = \"ASC\""
        $p1 = "unset($_SESSION["
    condition:
        all of ($s*) and #p1 == 5
}
