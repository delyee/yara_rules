rule UFRstealer: soft cnc
{
    meta:
        description = "UFR Stealer php gate"
        author = "delyee"
        date = "21.12.2019"
    strings:
        $ = "$cookiez = @$_COOKIE['pwd'];"
        $ = "$logout = $_GET['logout'];"
        $ = "#ufr_block"
        $ = "@unlink($dirname.'/'.$_GET['delete']);"
        $ = "if ($b == $pw)"
    condition:
        all of them
}
