rule azorult32_config_4fccf463297744dcb9d3b830475fb5a5: soft cnc
{
    meta:
        description = "config.php"
        author = "delyee"
        date = "22.01.2021"
        sha256sum = "1026b1e1e0d3b15ffddd5eaddd7495ab3130446554119094652beb37213f1f32"
    
    strings:
        $ = { 24 64 61 74 61 62 61 73 65 5f 6e 61 6d 65 20 3d 20 27 7a 6f 72 27 3b }
        $ = { 24 64 61 74 61 62 61 73 65 5f 75 73 65 72 20 3d 20 27 72 6f 6f 74 27 3b }
        
    condition:
        all of them
}



rule azorult32_functions_bb03cdbebf8c414e99a7fa6c1708ad31: soft cnc
{
    meta:
        description = "functions.php"
        author = "delyee"
        date = "22.01.2021"
        sha256sum = "cdd71f07bd8f6cf11354b954930fd403341c4ba12b5d57a49a89761c5a699cce"
    
    strings:
        $ = { 66 75 6e 63 74 69 6f 6e 20 46 69 6c 65 54 6f 53 74 72 69 6e 67 28 24 70 61 74 68 29 }
        $ = { 66 75 6e 63 74 69 6f 6e 20 70 61 72 73 28 24 68 74 6d 6c 2c 24 74 5f 2c 24 5f 74 29 7b }
        $ = { 66 75 6e 63 74 69 6f 6e 20 41 64 64 54 6f 46 69 6c 65 28 24 70 61 74 68 2c 20 24 64 61 74 61 29 }
        $ = { 66 75 6e 63 74 69 6f 6e 20 68 75 6d 61 6e 5f 66 69 6c 65 73 69 7a 65 28 24 62 79 74 65 73 2c 20 24 64 65 63 69 6d 61 6c 73 20 3d 20 32 29 20 7b }

    condition:
        3 of ($) 
}



rule azorult32_gate_6f89e8665b2c4392b7ce2a4deb885b52: soft cnc
{
    meta:
        description = "gate.php"
        author = "delyee"
        date = "22.01.2021"
        sha256sum = "590fea96c01b4c8d64f230122dfb5805ad31afbac77d6546fbf3d8f52b6fbe30"
    
    strings:
        $ = { 69 66 20 28 40 24 5f 50 4f 53 54 5b 27 67 65 74 63 6f 6e 66 69 67 27 5d }
        $ = { 69 66 20 28 40 24 5f 50 4f 53 54 5b 27 73 65 6e 64 72 65 70 6f 72 74 27 5d 21 }
        $ = { 69 6e 63 6c 75 64 65 5f 6f 6e 63 65 28 22 6d 6f 64 75 6c 65 73 2f 74 61 62 67 65 6f 5f 63 6f 75 6e 74 72 79 5f 76 34 2f 74 61 62 67 65 6f 5f 63 6f 75 6e 74 72 79 5f 76 34 2e 70 68 70 22 }
        $ = { 6d 6f 76 65 5f 75 70 6c 6f 61 64 65 64 5f 66 69 6c 65 28 40 24 5f 46 49 4c 45 53 5b 27 75 73 65 72 66 69 6c 65 27 5d 5b 27 74 6d 70 5f 6e 61 6d 65 27 5d 2c }
        
    condition:
        3 of ($)
}


rule azorult32_nickname_4fccf463297744dcb9d3b830475fb5a5: soft cnc
{
    meta:
        description = "..."
        author = "delyee"
        date = "22.01.2021"
    
    strings:
        $ = { 5b 68 74 74 70 73 3a 2f 2f 62 68 66 2e 69 6f 2f 6d 65 6d 62 65 72 73 2f 31 35 39 34 37 32 2f 5d }
        
    condition:
        all of them
}
