rule indoxploit_shell_v2: indoxploit phpshell
{
    meta:
        description = "New obfuscated version"
        author = "delyee"
        date = "07.08.2019"
    strings:
        //$s_q = "$_REQUEST[\"q\"]==\"1\"){echo \"200\"; exit;}"
        $s_eval = "eval(gzuncompress(base64_decode($_POST[\"chk\"])));"
        //$s_key = "if(isset($_POST[\"key\"])"
    condition:
        all of them
        //2 of ($s*)
}
