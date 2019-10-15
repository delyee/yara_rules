rule APT_IndoXploit_tmp_backdoor: indoxploit phpshell
{
    strings:
        $ = "if(file_exists($data[1]) && filesize($data[1]) !== 0) {"
        $ = "fopen("
        $ = "curl_init("
        $ = "'/tmp/sess_'.md5($_SERVER['HTTP_HOST']).'.php'"
        //$ = "echo '<script>window.location=\"?indoxploit\";</script>';"
    condition:
        all of them
}
