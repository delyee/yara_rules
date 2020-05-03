rule base64decode_get_post_post: inj
{
    meta:
        author = "delyee"
        date = "03.05.2020"
        sha256sum = "3a5c2f79d68aff979efce4cf0ad172d26162d34fd5097a973c45d41fff8af014"
    
    strings:
        $ = { 24 5f 50 4f 53 54 5b 22 [1-16] 22 5d 29 3b 65 78 69 74 }
        $ = { 26 26 69 73 73 65 74 28 24 5f 50 4f 53 54 5b 22 [1-16] 22 5d }
        $ = { 62 61 73 65 36 34 5f 64 65 63 6f 64 65 }
        
    condition:
        all of them
}
