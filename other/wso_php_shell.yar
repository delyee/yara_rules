/*
$auth_pass = "63a9f0ea7bb98050796b649e85481845";
$color = "#df5";
$default_action = 'FilesMan';
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
        $s5 = "if (!isset($_COOKIE[md5($_SERVER['HTTP_HOST'])]) || ($_COOKIE[md5($_SERVER['HTTP_HOST'])] != $auth_pass))"
        $s6 = "$default_charset"
        //$s7 = ""
    condition:
        all of them
}
