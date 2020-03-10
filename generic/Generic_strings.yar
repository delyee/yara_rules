private rule Generic_strings
{
    meta:
        description = "strings for Generic rule"
        author = "delyee"
        date = "10.03.2020"
    strings:
        $ = "$GLOBALS["
        $ = "]=Array"
        $ = "$_POST"
        $ = "$_GET"
        $ = "$_SESSION"
        $ = "$_SERVER"
        $ = "$_REQUEST"
        $ = "$_FILES"
        $ = "$_ENV"
        $ = "$_COOKIE"
        $ = "FilesMan"
        $ = "getDomainFromEmail"
        $ = "back_connect"
        $ = "function error_404"
        $ = "DDoS Perl IrcBot"
        $ = "SBCID_BOT_VERSION"
        $ = "wp__theme_icon"
        $ = "md5_brute"
    condition:
         any of them
}
