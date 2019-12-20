rule SmartStealerPHP_logs: soft cnc
{
    meta:
        description = "smartStealerPHP - logs.php"
        author = "delyee"
        date = "19.12.2019"
        sha256sum = "84e5e54a4610da7010589efeaa2a7db642901f4ceb46e8ae7ea68ee014cf8164"
    strings:
        $ = "$SQL = \"INSERT INTO logs (id, program, url, login, pass, computer, date, ip) VALUES (NULL, '$programName', '$urlAddress', '$loginName', '$passName', '$compName', '$dateVar', '$ipVar')\";"
        $ = "$compName = $_GET['comp'];"
        $ = "$dateVar = date('Y-m-d H:i:s');"
        $ = "$tableCreation = \"CREATE TABLE IF NOT EXISTS logs ("
    condition:
        all of them
}
