//include "Generic_strings.yar"
include "Generic_funcs.yar"

rule Generic: malicious
{
    meta:
        description = "Неизвестная версия"
        author = "delyee"
        date = "28.09.2019"
    condition:
    	Generic_funcs //and Generic_strings
}
