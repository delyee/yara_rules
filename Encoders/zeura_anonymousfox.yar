/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           то же самое что "any of them"
*/

rule zeura_anonymousfox: Encoders obfuscated malicious
{
    meta:
        description = "Anonymousfox group, zeura.com encoder"
        author = "delyee"
        date = "10-04-2022"
    strings:
        $title1 = "PHP Encode"
        $title2 = "by zeura.com"
        
        $file = "=file(__FILE__)"
        $eval = "eval("
        $base = "base64_decode("
        $halt = "__halt_compiler()"
    condition:
        2 of ($title*) or (#file == 1 and #eval == 3 and #base == 2 and $halt)
}
