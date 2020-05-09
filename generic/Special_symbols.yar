rule LineFeed_MoreTabs: generic malicious moretabs inj
{
    meta:
        author = "delyee"
        date = "12.04.2020"
    strings:
    // 09 09 09 09 09 09 09 09 0A x 480
        $pattern = { 0A 0A 09 09 09 09 09 09 09 09 09 09 09 (09 | 0A) 09 09 09 09 09 09 09 09 09 09 09 (09 | 0A) 09 09 09 09 09 09 09 09 09 09 09 (09 | 0A) 09 09 09 09 09 09 09 09 09 09 09 (09 | 0A) 09 09 09 09 09 09 09 09 09 09 09 (09 | 0A) 09 09 09 09 09 09 09 09 09 09 09 }
        //$pattern = { 0A 0A 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 [50-600] 09 09 09 09 09 09 09 09 }
    condition:
        $pattern
}

/*
rule LineFeed: generic malicious inj
{
    meta:
        author = "delyee"
        date = "04.05.2020"
    strings:
        $h1 = { 3c 3f }
        $h2 = { 0A 0A 0A 0A 0A 0A 0A 0A 0A 0A 0A 0A 0A 0A }
        $eval = { 65 76 61 6c (28 | 2f 2a) }
    condition:
        all of ($h*) and ($eval or Hex) and not IsELF and IsPHP //and not uint16(0) == 0xFFD8
}
*/
// 19
// 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a 0a

/*
rule LineFeed_MoreSpaces_Tab: generic malicious morespaces inj
{
    meta:
        description = "see example"
        author = "delyee"
        date = "12.04.2020"
    strings:
        $n_morespace_tab = { 0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 [50-600] 20 20 20 20 09 }
    condition:
        $n_morespace_tab and not CodeInjection
}


rule MoreTabs: generic moretabs inj
{
    meta:
        author = "delyee"
        date = "12.04.2020"
    strings:
        // $tabs = { 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 [50-600] 09 09 09 09 }
        $tabs = { 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 [50-600] 09 09 09 09 }
    condition:
        $tabs and not LineFeed_MoreTabs
}
*/