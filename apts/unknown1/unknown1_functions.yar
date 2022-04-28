rule unknown1_functions: apts phpshell
{
    meta:
        description = "functions.php"
        author = "delyee"
        date = "19.11.2021"

    strings:
        $isphp = "<?php"
        $unpack = "eval(strrev(htmlspecialchars_decode(gzinflate(base64_decode("

        $executor1 = "s9\x61Eg9SUfG\x63Vj\x62LUoqKSYg0gJzk1Jd7ELLU4MUkjtSQxJy0vsyodTdzYs\x43S/K\x426sHq6iuDi1q\x43\x413PzmvFKQ\x63q7\x43\x43nrp\x61eom1v\x62pGTmJZKg\x41\x3d"
        $executor2 = "gzuncompress(gzinflate(gzuncompress(gzinflate(str_rot13(base64_decode(gzinflate(base64_decode(strrev("

        $base_rev1 = "H0v//nNhPgXLSOJvAkHSgMxDd9pVvaOLwB/PiVtTMFVtqrRSX50aa9fAEJC8UkHVrPj3XX388vTEqbItArCaEyz8mojqsgkJ/Q0U1+1w5HBHtzLZV+"
        $base_rev2 = "a2Et3Q6XGlwNkMlzknPmsayUk4aVWKDlxPtS3VuSdvv17qzZrk5TUgqLr61DMWDavgVEagI2h90BroRHho/0KEHogNUaAclksR4vi"
        $base_rev3 = "euHIFl1IPzFEMhFAsU50GN8NBLmNdk1qT1bBAeILWYRSbtFfAGa3ZOrln5N75nOVo1C5ThofJ07TJTjP44hffvxnrsn7nL6ctXK"
        $base_rev4 = "kpn6d+xbHPziEtdGYpX6dWxdqqrArVzhN896nfHcJ3N3CAPa5AAi/QEEA1qt1eZD"

        //$base_normal1 = ""
        //$base_normal2 = ""
        //$base_normal3 = ""
        //$base_normal4 = ""

    condition:
        $isphp and ($unpack and (2 of ($base_rev*)) or any of ($executor*))
}
