rule FalsePositive_ZyX_SimpleForm2: FalsePositive
{
    meta:
        description = "Модуль конструктор формы обратной связи simpleForm2 для Joomla"
        author = "delyee"
        date = "14.10.2019"
        sha256sum = "421b9fd4dffdd5598765dc364728fc62da34537307c88530c6b72ca7e9b528de"
    strings:
        $username = "ZyX"
        $url = "allforjoomla.ru" nocase
        $simpleform = "SimpleForm2"
    condition:
        all of them
}
