include "../is/index.yar"

rule extract_backdoor: generic ioc
{
    meta:
        description = "https://blog.sucuri.net/2014/02/php-backdoors-hidden-with-clever-use-of-extract-function.html"
        author = "delyee"
        date = "09.07.2021"
        sha256sum = ""
    
    strings:
        $ = { 40 65 78 74 72 61 63 74 20 28 24 5F 52 45 51 55 45 53 54 29 3B }
        
    condition:
        all of them and not IsELF
}