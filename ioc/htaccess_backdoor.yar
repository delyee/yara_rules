rule htaccess_backdoor: malicious backdoor
{
    meta:
        description = "Disguise PHP code in other extensions - .txt, .mp3/etc"
        description = "https://www.php.net/manual/ru/security.hiding.php"
        author = "delyee"
        date = "26.03.2020"
    strings:
        $ = "AddType application/x-httpd-php"
    condition:
        all of them
}
