/*
"20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20" * 20 = 320 spaces
Example: ("0x20"*320)
</body>
</html>

                                                                                                                                                                                           	<script type="text/javascript">var _0x3a1f=["\x73\x70\x6C\x61\x73\x68\x5F\x69","\x3D"
*/

/*
0x20 - Space
0x0A - Line Feed
0x09 - Horizontal Tab
*/

rule LineFeed_MoreSpaces_Tab: generic malicious morespaces
{
    meta:
        description = "see example"
        author = "delyee"
        date = "12.04.2020"
    strings:
        $n_morespace_tab = { 0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 [50-600] 20 20 20 20 20 20 20 20 09 }
    condition:
        $n_morespace_tab
}

rule CodeInjection: generic malicious inj morespaces
{
    meta:
        author = "delyee"
        date = "12.04.2020"
    strings:
        $inj = { (3c 3f | 70 68 70) 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }
        // (20 20 20 20 20 20 20 20) * 7
        
        //$spaces = { (3c 3f | 70 68 70) 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }
        // $spaces = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 [50-] 20 20 20 20 }
    condition:
        $inj
}

rule LineFeed_MoreTabs: generic malicious moretabs
{
    meta:
        author = "delyee"
        date = "12.04.2020"
    strings:
        $pattern = { 0A 09 09 09 09 09 09 09 09 [50-600] 09 09 09 09 09 09 09 09 }
    condition:
        $pattern
}

rule MoreTabs: generic malicious
{
    meta:
        author = "delyee"
        date = "12.04.2020"
    strings:
        $tabs = { 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 [50-600] 09 09 09 09 }
    condition:
        $tabs and not LineFeed_MoreTabs
}