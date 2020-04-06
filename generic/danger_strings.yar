rule danger_strings: generic
{
    strings:
        $ = "getDomainFromEmail"
        $ = "back_connect"
        $ = "function error_404"
        $ = "DDoS Perl IrcBot"
        $ = "SBCID_BOT_VERSION"
        $ = "wp__theme_icon"
        $ = "md5_brute"
    condition:
        any of them
