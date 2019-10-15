rule dae3880146c34a5ead80eb65df27379c: cncrypto unknown
{
    meta:
        description = ""
        author = "delyee"
        date = "14.10.2019"
        sha256sum = "3205acdb172c292a44304ebec8ed8d47d4e99309644d8d98bb6d092d54029438"
    strings:
        $ = "<?php $_0OO=__FILE__"
        $ = "shnorl94APwCBJsjTPWKHKBTRSaqq19GT05QzhsMrznorlRlkuCKuP4KcQ9gNaDNBRsaNQBtDQq"
        $ = "jy9dkT5rcKN7euX3kuBUkyCwu0DaRadKbgwKuPJ7b2aMiPWKDuXJrgxKLKBebUN2xTtJiGCpjPN8cQw"
    condition:
        all of them
}
