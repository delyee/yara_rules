rule register_shutdown_function: apts neapolitan backdoor 
{
    meta:
        description = "https://blog.sucuri.net/2019/08/neapolitan-backdoor-injection.html"
        author = "delyee"
        date = "28-04-2022"
    strings:
        $ = "@register_shutdown_function(create_function(${"
    condition:
        all of them
}
