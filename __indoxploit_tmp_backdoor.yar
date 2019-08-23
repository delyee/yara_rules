rule APT_IndoXploit_tmp_backdoor: indoxploit phpshell
{
    strings:
        $ = "echo '<script>window.location=\"?indoxploit\";</script>';"
    condition:
        all of them
}
