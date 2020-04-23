rule FOPO: Encoders obfuscated
{
    meta:
        description = "FOPO - Free Online PHP Obfuscator"
        readme = "https://github.com/Antelox/FOPO-PHP-Deobfuscator"
    strings:
        $ = /\$[a-zA-Z0-9]+=\"\\(142|x62)\\(141|x61)\\(163|x73)\\(145|x65)\\(66|x36)\\(64|x34)\\(137|x5f)\\(144|x64)\\(145|x65)\\(143|x63)\\(157|x6f)\\(144|x64)\\(145|x65)\";@eval\(/
    condition:
        all of them
}
