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

/* More_chars.yar(23): warning: $n_morespace_tab is slowing down scanning (critical!)


*/

rule CodeInjection: generic malicious morespaces inj
{
    meta:
        author = "delyee"
        date = "12.04.2020"
    strings:
        $ = { (3c 3f | 70 68 70) 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }
        // (20 20 20 20 20 20 20 20) * 7
        //$spaces = { (3c 3f | 70 68 70) 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }
        // $spaces = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 [50-] 20 20 20 20 }
    condition:
        all of them
}

