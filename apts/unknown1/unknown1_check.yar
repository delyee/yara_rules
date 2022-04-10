rule unknown1_check: apts php
{
    meta:
        description = "check.php"
        author = "delyee"
        date = "19.11.2021"

    strings:
        $isphp = "<?php"

        $header1 = "header(\"Access-Control-Allow-Origin: *\");"
        $header2 = "header(\"Content-Type: application/json; charset=UTF-8\");"

        $response1 = "$response['status'] = 'success';"
        $response2 = "$response['server_ip'] = getHostByName(php_uname('n'));"
        
        $exit = "exit(json_encode($response));"

    condition:
        $isphp and all of ($header*) and all of ($response*) and $exit
}