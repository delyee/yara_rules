/* Example:
"\x47\x4c\x4f\x42\x41\x4c\x53"
"\x47\x4cO\x42\x41\x4c\x53"
"\x47\x4c\x4f\x42\x41\x4c\x53"
"\x47\x4c\x4fB\x41\x4c\x53"
"\x47L\x4f\x42\x41\x4c\x53"
"\x47\x4c\x4f\x42\x41\x4cS"
"G\x4c\x4f\x42\x41\x4c\x53"
"\x47\x4c\x4f\x42A\x4c\x53"
*/
private rule Globals
{
    meta:
        author = "delyee"
        date = "26.03.2020"
    strings:
        $g = "\\x47"
        $l = "\\x4c" nocase
        $o = "\\x4f" nocase
        $b = "\\x42"
        $a = "\\x41"
        $s = "\\x53"
    condition:
        all of them
}

private rule Eval
{
    meta:
        author = "delyee"
        date = "26.03.2020"
    strings:
        $e = "\\x65"
        $E = "\\x45"
        $v = "\\x76"
        $V = "\\x56"
        $a = "\\x61"
        $A = "\\x41"
        $l = "\\x6c" nocase
        $L = "\\x4c" nocase
        // 45 56 41 4c
    condition:
        ($e or $E) and ($v or $V) and ($a or $A) and ($l or $L)
}

private rule Base64decode
{
    // 62 61 73 65 36 34 5f 64 65 63 6f 64 65
    // 42 41 53 45 36 34 5f 44 45 43 4f 44 45
    meta:
        author = "delyee"
        date = "26.03.2020"
    strings:
        $b = "\\x62"
        $B = "\\x42"
        $a = "\\x61"
        $A = "\\x41"
        $s = "\\x73"
        $S = "\\x53"
        $e = "\\x65"
        $E = "\\x45"
        $six = "\\x36"
        $four = "\\x34"
        $lowline = "\\x5f" nocase
        $d = "\\x64"
        $D = "\\x44"
        $c = "\\x63"
        $C = "\\x43"
        $o = "\\x6f" nocase
        $O = "\\x4f" nocase

    condition:
        ($b or $B) and ($a or $A) and ($s or $S) and (#e == 2 or #E == 2) and ($six and $four and $lowline) and (#d == 2 or #D == 2) and ($e or $E) and ($c or $C) and ($o or $O)
}


rule Hex_Obfuscated: malicious obfuscated
{
    meta:
        description = "hex encoded"
        author = "delyee"
        date = "14.02.2020"
    //strings:
        //$eval = "\\x65\\x76\\x61\\x6C"
        //$gzinflate = "\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65"
        //$base64_decode = "\\x62\\x61\\x73\\x65\\x36\\x34\\x5F\\x64\\x65\\x63\\x6F\\x64\\x65"
        //$globals = "\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53"
        //todo: eVaL, EvAl, evAL, ...
    condition:
        Eval or Base64decode or Globals
}
*/