// по тестам, md5 быстрее любого sha*, так что придется использовать md5, если важна скорость на дистанции (файлов больше 100к)
// засунул всё в один файл для прироста скорости скана
import "hash"



// xmrig_md5_5_9_0
private rule tar_gz_5_9_0
{
	meta:
		description = "xmrig-5.9.0-xenial-x64.tar.gz"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "b63ead42823ae63c93ac401e38937323"
}

private rule xmrig_5_9_0
{
	meta:
		description = "xmrig.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "d351de486d4bb4e80316e1524682c602"
}

private rule xmrig_notls_5_9_0
{
	meta:
		description = "xmrig-notls.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "187ed1d112e4a9dff0241368f2868615"
}


rule xmrig_md5_5_9_0: mining md5 xmrig
{
    meta:
        description = "md5 list"
        author = "delyee"
        date = "09.05.2019"
    condition:
        tar_gz_5_9_0 or xmrig_5_9_0 or xmrig_notls_5_9_0
}



// xmrig_md5_5_10_0
private rule tar_gz_5_10_0
{
	meta:
		description = "xmrig-5.10.0-xenial-x64.tar.gz"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "416079fd0c7b45307556198f3f67754d"
}

private rule xmrig_5_10_0
{
	meta:
		description = "xmrig.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "3939395192972820ce2cf99db0c239d7"
}

private rule xmrig_notls_5_10_0
{
	meta:
		description = "xmrig-notls.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "0456ef39240c75e0862b30419d4c6359"
}


rule xmrig_md5_5_10_0: mining md5 xmrig
{
    meta:
        description = "md5 list"
        author = "delyee"
        date = "09.05.2019"
    condition:
        tar_gz_5_10_0 or xmrig_5_10_0 or xmrig_notls_5_10_0
}



// xmrig_md5_5_11_0
private rule tar_gz_5_11_0
{
	meta:
		description = "xmrig-5.11.0-xenial-x64.tar.gz"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "abf7feaf1e456c0fc6e8f1e40af9211c"
}

private rule xmrig_5_11_0
{
	meta:
		description = "xmrig.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "56aec7d8d2aba5ba2b82930408f0b5d3"
}

private rule xmrig_notls_5_11_0
{
	meta:
		description = "xmrig-notls.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "9a5c0a5d960b676ba4db535f71ee7cef"
}


rule xmrig_md5_5_11_0: mining md5 xmrig
{
    meta:
        description = "md5 list"
        author = "delyee"
        date = "09.05.2019"
    condition:
        tar_gz_5_11_0 or xmrig_5_11_0 or xmrig_notls_5_11_0
}



// xmrig_md5_5_11_1
private rule tar_gz_5_11_1
{
	meta:
		description = "xmrig-5.11.1-xenial-x64.tar.gz"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "820022ba985b4d21637bf6d3d1e53001"
}

private rule xmrig_5_11_1
{
	meta:
		description = "xmrig.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "0090962752b93454093239f770628006"
}

private rule xmrig_notls_5_11_1
{
	meta:
		description = "xmrig-notls.elf"
		author = "delyee"
        date = "09.05.2019"
	condition:
		hash.md5(0, filesize) == "54158be61b8011a10d1a94432ead208c"
}


rule xmrig_md5_5_11_1: mining md5 xmrig
{
    meta:
        description = "md5 list"
        author = "delyee"
        date = "09.05.2019"
    condition:
        tar_gz_5_11_1 or xmrig_5_11_1 or xmrig_notls_5_11_1
}