import hash

rule xmrig_tar_gz: mining xmrig md5
{
    meta:
        description = "https://github.com/MoneroOcean/xmrig_setup"
        author = "delyee"
        date = "07.05.2020"
    condition:
        hash.md5(0, filesize) == "0d4e646dff5399b35295514fbeb0a4a7"
}


rule setup_moneroocean_miner: bash mining xmrig md5
{
    meta:
        description = "https://github.com/MoneroOcean/xmrig_setup"
        author = "delyee"
        date = "07.05.2020"
    strings:
        $ = "MoneroOcean mining setup script"
        $ = "setup_moneroocean_miner.sh <wallet address>"
        $ = "TOTAL_CACHE=$(( $CPU_THREADS*$CPU_L1_CACHE + $CPU_SOCKETS"
        $ = "$HOME/moneroocean/xmrig"
        $ = "$LATEST_XMRIG_LINUX_RELEASE"
        $ = "moneroocean_miner.service"
        $ = ""
    condition:
        any of them or hash.md5(0, filesize) == "75363103bb838ca8e975d318977c06eb"
}


rule uninstall_moneroocean_miner: bash mining xmrig md5
{
    meta:
        description = "https://github.com/MoneroOcean/xmrig_setup"
        author = "delyee"
        date = "07.05.2020"
    strings:
        $ = "MoneroOcean mining uninstall script"
        $ = "sudo systemctl stop"
        $ = "sudo systemctl disable"
        $ = "rm -f /etc/systemd/system/"
        $ = "sudo systemctl daemon-reload"
    condition:
        3 of them or hash.md5(0, filesize) == "b059718f365d30a559afacf2d86bc379"
}