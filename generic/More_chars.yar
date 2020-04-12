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

rule LineFeed_and_MoreSpaces_and_Tab: generic malicious
{
    meta:
        description = "see example"
        author = "delyee"
        date = "12.04.2020"
    strings:
        $pattern = { 0A 20 20 20 20 [20-] 20 20 20 20 09 }
    condition:
        $pattern
}

rule MoreSpaces: generic malicious
{
    meta:
        author = "delyee"
        date = "12.04.2020"
    strings:
        $spaces = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 [20-] 20 20 20 20 }
    condition:
        $spaces and not LineFeed_and_MoreSpaces_and_Tab
}

rule LineFeed_and_MoreTabs: generic malicious
{
    meta:
        author = "delyee"
        date = "12.04.2020"
    strings:
        $pattern = { 0A 09 09 09 09 [20-] 09 09 09 09 }
    condition:
        $pattern
}

rule MoreTabs: generic malicious
{
    meta:
        author = "delyee"
        date = "12.04.2020"
    strings:
        $tabs = { 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 [20-] 09 09 09 09 }
    condition:
        $tabs and not LineFeed_and_MoreTabs
}