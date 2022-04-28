rule i0_php_backdoor: phpshell i0 apts
{
  meta:
      description = "i0 php backdoor"
      author = "delyee"
      date = "05.08.2019"
      sha256sum = "5158c960fd305a1c6d4dfb469f45550c2952c049ca6a9db87605040556b2c558"

    strings:
        $func_exec = "if (function_exists('exec')) {"
        $func_passthru = "} elseif (function_exists('passthru')) {"
        $func_system = "} elseif (function_exists('system')) {"
        $system = "@system($in);"
    condition:
        all of them
}
