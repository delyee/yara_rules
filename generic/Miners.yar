/*
https://github.com/fireice-uk/xmr-stak
https://github.com/hyc/cpuminer-multi
https://github.com/xmrig/xmrig

// 7f 45 4c 46
//import "elf"
*/

rule GenericMiner: miner
{
    meta:
        description = ""
        author = "delyee"
        date = "16.04.2020"
    strings:
        //$elf = { 7f 45 4c 46 }
        $pool1 = "nicehash.com" ascii fullword nocase
        $pool2 = "minergate.com" ascii fullword
        $pool3 = "hashvault.pro"
        $pool4 = ".monero.org" ascii fullword nocase
        $pool5 = ".minexmr.com" ascii fullword
        $pool6 = "monerohash.com" ascii fullword
        $pool7 = ".poolto.be" ascii fullword
        $pool8 = "dwarfpool.com" ascii fullword
        $pool9 = ".xmrpool.net" ascii fullword

        //$s1 = "xmr" fullword ascii
        $s2 = "monero" ascii
        $s3 = "hashrate" ascii
        $s4 = "--donate-level" ascii
        $s5 = "--nicehash" ascii
        $s7 = "xmrig" fullword nocase ascii
        $s8 = "stratum+tcp" ascii
        $s9 = "stratum+udp" ascii

    condition:
        // at elf.entry_point and
        any of ($pool*,$s*)
        //all of them
}