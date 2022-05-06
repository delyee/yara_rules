rule visa_mastercard_v1: phishing
{
    meta:
        description = "фейк для кражи данных дебетовых карт (исходник https://github.com/muhammed/vue-interactive-paycard) - oplata-master.ru (06.05.2022 17_41_56).html"
        author = "delyee"
        date = "06-05-2022"
    strings:
        $p1 = "<title>Free-Kassa</title>"
        $p2 = "<form method='POST' action='cardHandler.php' class='credit-card-form__form"
        
        $m1 = "class=\"card-item__dateTitle\">ММ/ГГ</label>"
        $m2 = "class=\"card-input__label\">CVV</label>"
        $m3 = "class=\"card-input__label\">Номер карты</label>"
        $m4 = "class=\"card-input__label\">Срок действия</label>"
        $m5 = "class=\"card-input__label\">Имя на карте</label>"
        $m6 = "class=\"card-input__label\">Срок действия</label>"
        $m7 = ">Сумма к оплате</h3>"
    condition:
        all of ($p*) or 5 of ($m*) 
}
