include "Generic_Eval.yar"
include "Generic_v2.yar"
include "test_eval_evasion.yar"

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