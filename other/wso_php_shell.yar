/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           тоже самое что "any of them"
*/

rule other_wso_php_shell: phpshell
{
    meta:
        description = "default wso shell"
        author = "delyee"
        reference = "https://github.com/delyee/yara_rules"
        date = "29.09.2019"
        sha256sum = "b2ffeeeb46add3430bdb3f3a301126b35a4e5563011c3b3dcefd3923d1427037"
    strings:
        $s1 = "$auth_pass"
        $s2 = "$default_action"
        $s3 = "WSO_VERSION"
        $s4 = "function wsoLogin() {"
        $p1 = "if (!isset($_COOKIE[md5($_SERVER['HTTP_HOST'])]) || ($_COOKIE[md5($_SERVER['HTTP_HOST'])] != $auth_pass))"
    condition:
        3 of ($s*) and $p1
}
