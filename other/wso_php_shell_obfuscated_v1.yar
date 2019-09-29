rule other_wso_php_shell_obfuscated_v1: phpshell
{
    meta:
        description = "obfuscated wso shell"
        author = "delyee"
        reference = "https://github.com/delyee/yara_rules"
        date = "29.09.2019"
        sha256sum = "eb4692ca53eb5d1a5917a088a1ca5946bc48a27d7a87e969de645a86a12c1d12"
    strings:
        $ = "<?php eval(gzinflate(base64_decode('HZzHkuNQdgV/ZXYzE1jAu5BCE/CW8JYbBbz3Hl8vlhbdm64iAbx3z8lkg/jP//z3f+Z6/kdxJv2/qrcZyz7Zi3+lyVYQ2P/mRTblxb/+KX9fuZs+TN4F4O2dlsjsjzZRtOOoX1YVUH3UzSGhUNKPUL/RqBygcNTRQXCmQTA6lvkElZZsSQccfZuWxRAkLFXEX+Y8S10AZd0C5RJaHYUM37QI9sBoTSoMv3viNFAQm1afx7wpJSEhsNmq01ccP4/1acjHcRjOu10iZgTGfWT1teuwYpwck5ERspP9cpJLGKeYujdbvg2faz4Vzz6zl9ef45HcdrP8mue8qGqfwu4iTN0/+YErSd2tEpKgtFSamBuhnjfS0qMOMXhqcRfqbYfo8+PUHXZrZOd2D3ugu1xoKu2Kkz5uL8sOzRpsHzKPSbVvcTH3MPzDbcjHSG/SnCqOw+"
    condition:
        any of them
}
