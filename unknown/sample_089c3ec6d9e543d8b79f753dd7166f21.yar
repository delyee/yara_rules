/*
all of them         все строки внутри правила
any of them         любая строка в правиле
all of ($a*)        все строки чей идентификатор начинается с $a
any of ($a,$b,$c)   любая из $a,$b или $c
1 of ($*)           то же самое что "any of them"
*/

rule sample_089c3ec6d9e543d8b79f753dd7166f21: tr dropper pasca
{
    meta:
        description = ""
        author = "delyee"
        date = "14.12.2019"
        sha256sum = "4613165b62ac6870f280d0d9c5cdfcbb5824716bc749fc5b1ca4808f3a1e6db8"
    strings:
        $ = "#p@$c@#"
        $ = "($_FILES[\"filename\"][\"tmp_name\"]))"
        $ = "move_uploaded_file/*;*/($_FILES[\"filename\"][\"tmp_name\"]"
    condition:
        all of them
}
