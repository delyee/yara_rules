rule APT_i0_shell_backdoor: phpshell i0
{
  meta:
      description = "[APT][i0][SHELL]"
      author = "delyee"
      date = "05.08.2019"

    strings:
        $func_exec = "if (function_exists('exec')) {"
        $func_passthru = "} elseif (function_exists('passthru')) {"
        $func_system = "} elseif (function_exists('system')) {"
        $system = "@system($in);"
    condition:
        all of them
}
