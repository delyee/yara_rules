rule vk_auth_v1: phishing
{
    meta:
        description = "фейк vk.com - вход - standstore.ru (04.05.2022 22_32_03).html"
        author = "delyee"
        date = "04-05-2022"
    strings:
        $title = "<title>Вход | ВКонтакте</title>"
        $err1 = "<b>Не удаётся войти.</b>"

        $m1 = ">Вход ВКонтакте<" nocase
        
        $p1 = "Чтобы выполнить это действие, нужно зайти на сайт" nocase
        $p2 = "Не удаётся войти" nocase
        $p3 = "Если Вы всё внимательно проверили, но войти всё равно не удаётся, Вы можете <b><a href=\"https://vk.com/restore\"> нажать сюда</a></b>"
        $p4 = "Пожалуйста, введите код, который Вы только что получили"
        $p5 = "Чужой компьютер"
    condition:
        $title and $err1 or $m1 and 3 of ($p*) 
}
