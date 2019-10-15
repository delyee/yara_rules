/*
@delyee
sha256sum: 7863e4b7854b6f3e376b7781d0343c7ff67bd477bc08f8ba5a1c59a2c08083b2
filename: dk.py
*/


rule i0_python_backdoor: python backdoor phpshell i0
{
  meta:
      description = "i0 python backdoor"
      author = "delyee"
      date = "05.08.2019"
      sha256sum = "7863e4b7854b6f3e376b7781d0343c7ff67bd477bc08f8ba5a1c59a2c08083b2"

    strings:
        $s1 = "l1llll_dk_ = sys.version_info [0] == 2"
        $s2 = "l1ll1lll_dk_ = 2048"
        $s3 = "l11111ll_dk_ = l1lllll_dk_ [:-1]"
    condition:
        all of them
}
