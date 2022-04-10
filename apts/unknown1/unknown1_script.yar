import "hash"

rule unknown1_script: apts zip
{
	meta:
        description = "script.zip"
        author = "delyee"
        date = "19.11.2021"

    condition:
        hash.md5(0, filesize) == "ac3fdd1b1db68e6ebc8ba2ca76dd8126"
}