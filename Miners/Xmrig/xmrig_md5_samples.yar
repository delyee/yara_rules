import "hash"

rule xmrig_md5_samples_1: mining md5 xmrig
{
	meta:
		description = ""
		author = "delyee"
        date = "10.05.2019"
	condition:
		hash.md5(0, filesize) == "6f2a2ff340fc1307b65174a3451f8c9a"
}


rule xmrig_md5_samples_2: mining md5 xmrig
{
	meta:
		description = "wallet UPX1cr4av27axYT9XeCmwe3nP91MyDhx177N2e3aS8SB8RDqe4YGtnB12FuhMGuNjZULCwvSNbg9EUehJQrCBwoG1i6vPn95h5"
		author = "delyee"
        date = "13.01.2021"
	condition:
		hash.md5(0, filesize) == "22a213bfd093c402312d75f5f471505e"
}