rule a8b0d46ed08445e999dd77bc7ca04646: phpshell
{
    meta:
        description = "dgreusdi"
        author = "delyee"
        date = "05.08.2019"
        sha256sum = "6452039c95cf77d834e2eaa1459abf4e176c1f7158f2b86751138e5bd24e072e"
    strings:
        $ = "eval(\"\\n\\$dgreusdi = intval(__LINE__)"
    condition:
        any of them
}
