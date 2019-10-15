/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           то же самое что "any of them"
*/

rule oxycodone_phpshell: phpshell
{
    meta:
        description = "https://www.unphp.net/decode/08bc200bc913e175886d8296cfa2cd58/"
        author = "delyee"
        date = "14.10.2019"
        sha256sum = "7f2744426ee68e475aea85e3a115162d1640ebae773cb269ba2e3acdb8bf6fc4"
    strings:
        $ = "eval(gzuncompress(base64_decode('eF6FVlGPmkAQ/it9aOJd0jQnelbS+OA9gCFXGm0KyzaNgUVDFDxzaE"
        $ = "eval(gzuncompress(base64_decode('eF61WG1vo0YQ/iuOhQI0BMyLAZ9LT1c1d/ch7Z1yab8kroXx2sbGgH"
    condition:
        all of them
}
