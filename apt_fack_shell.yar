rule APT_fack_shell: indoxploit phpshell
{
  meta:
      description = "[APT][IndoXploit][SHELL]"
      author = "delyee"
      date = "05.08.2019"
    strings:
        $q = "if ($_GET['q']=='1'){echo '200'; exit;}"
        $key = "if($_GET['key']=='sdfadsgh4513sdGG435341FDGWWDFGDFHDFGDSFGDFSGDFG')eval(base64_decode($_POST['fack']));"
        $key_md5 = "if(md5($_GET['key'])=='7663f1b3555993ad229183b0efad3261')eval(base64_decode($_POST['fack']));"
    condition:
        all of them
}


rule APT_fack_obfuscated_shell: indoxploit phpshell
{
    meta:
        description = "New obfuscated version"
        author = "delyee"
        date = "07.08.2019"
    strings:
        $s_q = "$_REQUEST[\"q\"]==\"1\"){echo \"200\"; exit;}"
        $s_eval = "eval(gzuncompress(base64_decode($_POST[\"chk\"])));"
        $s_key = "if(isset($_POST[\"key\"])"
    condition:
        2 of ($s*)
}
