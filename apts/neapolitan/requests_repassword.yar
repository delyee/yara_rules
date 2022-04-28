rule requests_repassword: apts neapolitan backdoor 
{
    meta:
        description = "https://blog.sucuri.net/2019/08/neapolitan-backdoor-injection.html"
        author = "delyee"
        date = "27-04-2022"
    strings:
        $ = "if($REQUEST[re_password]!=$REQUEST[RE_password]){extract($REQUEST"
        $ = "usort($login,$password"
    condition:
        all of them
}
