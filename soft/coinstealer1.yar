rule CoinStealer: soft cnc
{
    meta:
        description = "CoinStealer v1.1 Bitcoin Stiller"
        author = "delyee"
        date = "19.12.2019"
        sha256sum = "de3e1324bd69d64c37f931a82e02d540bcc210cc9bd874a25de61ade6d86891e"
    strings:
        $ = "if(strcmp($_POST['skey'], $SecretKey)"
        $ = "if($_POST['action']== \"newwallet\")"
        $ = "if($_POST['ext'] == \"wallet\" || $_POST['ext'] == \"dat\")"
    condition:
        all of them
}
