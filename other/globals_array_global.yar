rule globals_array_global: inj
{
    meta:
        description = ""
        author = "delyee"
        date = "03.05.2020"
        sha256sum = "21d781051b188ded774ef7c7b115b52b3a5f19504000a8967a34e4c30d8e78e0"
    
    strings:
        $h1 = { 3c 3f 70 68 70 }
        $h2 = { 24 [4-12] 4e 55 4c 4c }
        $eval_escaping = { 65 76 61 6c 2f 2a }
        $eval = { 65 76 61 6c 28 }
        
    condition:
        all of ($h*) and ($eval_escaping or $eval) and not IsELF
}
