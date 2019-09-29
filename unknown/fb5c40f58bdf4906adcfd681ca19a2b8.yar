rule fb5c40f58bdf4906adcfd681ca19a2b8: phpshell
{
    meta:
        description = "sessdt mailer"
        author = "delyee"
        date = "30.09.2019"
        sha256sum = "60836155cdcccda3348214d1b0ce7a09dd31c3a74bf9dbf7f20bf1e35da935f0"
    strings:
        $ = "$smv=$_POST['smv'];"
        $ = "$realname=$_POST['realname'];"
        $ = "$emaillist=$_POST['emaillist'];"
        $ = "if($_COOKIE[$sessdt_k]==\"102\") {"
    condition:
        all of them
}
