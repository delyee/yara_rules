include "Generic.yar"
include "default_shell.yar"
//include "danger_strings.yar"
//include "Generic_Eval.yar"
include "test_eval_evasion.yar"
include "CodeInjection.yar"
include "Special_symbols.yar"

/*
rule Long_Generic: malicious obfuscated
{
  meta:
      author = "delyee"
      date = "20.10.2019"
    condition:
        filesize > 5K and (Generic_Eval or Generic_v2)
}


rule Generic: malicious obfuscated
{
    meta:
        author = "delyee"
        date = "20.10.2019"
    condition:
        Generic_Eval or Generic_v2

}
*/
