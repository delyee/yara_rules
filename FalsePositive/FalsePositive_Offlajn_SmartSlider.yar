rule FalsePositive_Offlajn_SmartSlider: FalsePositive
{
    meta:
        description = "http://offlajn.com/"
        author = "delyee"
        date = "14.10.2019"
        sha256sum = "bcbf9ec4301f39bb0aece9fcd4c2b7474efd3fde53722975571094d513cb20a9"
    strings:
        $ = "smartslider - Smart Slider"
        $ = "function SmartSlidersChecks()"
        $ = "$SystemJoCode = $UnixTimeLastEdit.$ExtensionAuthor.$ExtensionName.$MainDomain;"
        $ = "echo eval(base64_decode($SystemJoCode));"
        $ = "Copyright (c) Offlajn.com"
    condition:
        all of them
}
