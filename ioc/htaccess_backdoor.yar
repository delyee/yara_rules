rule htaccess: generic ioc
{
    meta:
        description = "Disguise PHP code in other extensions - .txt, .mp3/etc"
        description = "https://www.php.net/manual/ru/security.hiding.php"
        author = "delyee"
        date = "26.03.2020"
    strings:
    	$ = "AddHandler application/x-httpd-php"
        $ = "AddType application/x-httpd-php"
    condition:
        any of them
}
