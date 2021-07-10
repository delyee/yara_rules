/*
levifuksz_shells [phpshell] ./shellm.php
levifuksz_shells [phpshell] ./shellmp.php
levifuksz_shells [phpshell] ./shellp.php
levifuksz_shells [phpshell] ./shell.php
*/

rule levifuksz_shells: phpshell
{
    meta:
        description = "https://github.com/levifuksz/php-shell/"
        author = "delyee"
        date = "09.07.2021"
        sha256sum = "a5a52e838ca63d271e6761101fd930c20dadca2cac4b8dff798f69f8a28da0b3"
    
    strings:
        $ = { 24 5F 3D 40 24 7B 22 5F 24 5F 22 7D 5B 27 5F 27 5D 3F 24 7B 22 5F 24 5F 22 7D 5B 27 5F 27 5D 28 22 22 2C 24 7B 22 5F 24 5F 22 7D 5B 24 5F 5D 29 3A 27 27 3B }
        
    condition:
        all of them and not IsELF
}