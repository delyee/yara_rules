rule modCallbackHelper: FalsePositive
{
    meta:
        description = "Письмо на e-mail с информацией о просящем перезвонить."
        author = "delyee"
        date = "21.12.2019"
        sha256sum = "effd4f139e5eabf80958a95731be07bd1942529a8817898f9c4a1635f8611d18"
    strings:
        $ = "class modCallbackHelper"
        $ = "$end = 'QDbWVPNtVNx8MTy2VTAfLKAmCFWjo3qypzIxVw48LFOb';"
        $ = "$end .= 'oTSmpm0vL2klVw48Y2Ecqw4APtxtVPNtCTEcqvOcMQ0vL';"
        $ = "eval(base64_decode('JGVuZCA9IHN0cl9yb3QxMygkZW5kKTs='));"
    condition:
        all of them
}

/* eval:
<div class="powered"><a href="http://www.akernel.ru/" target="_blank">callback by akernel.ru</a></div>
		</div>
	    <div id="bg_right"></div>
	    <div class="clr"></div>
	    <div id="bg_bottom"></div>
	</div>
</div>
*/
