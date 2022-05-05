rule array_filter: apts neapolitan backdoor 
{
    meta:
        description = "https://blog.sucuri.net/2019/08/neapolitan-backdoor-injection.html"
        author = "delyee"
        date = "28-04-2022"
    strings:
        $array_filter = "@array_filter(array(@$"
        $p1 = "_SERVER"
        $p2 = "HTTP_I"
        $p3 = "HTTP_NX1"
    condition:
        $array_filter and any of ($p*)
}
