rule other_wso_php_shell_obfuscated_v1: phpshell
{
    meta:
        description = "obfuscated wso shell"
        author = "delyee"
        date = "29.09.2019"
        sha256sum = "eb4692ca53eb5d1a5917a088a1ca5946bc48a27d7a87e969de645a86a12c1d12"
    strings:
        $ = "eval(gzinflate(base64_decode('HZzHkuNQdgV/ZXYzE1jAu5BCE/CW8JYbBbz3Hl8vlhbdm64iAbx3z8lkg/jP//z3f+Z6/kdxJv2/qrcZyz7Zi3+lyVYQ2P/mRTblxb/"
    condition:
        all of them
}
