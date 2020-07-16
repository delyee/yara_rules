## Hello 

In this repository you can find absolutely free yara rules for searching for php shells and
other malicious software.

I hope this will be useful for organizations that provide hosting services, as well as specialists who are engaged in cleaning customers of malware.

This project with one person in exclusively free time, made just4fun and therefore please do not judge strictly. If you have a desire to help, then contacts for communication are [here](https://delyee.github.io/contact) or immediately make a pull request ([template](https://github.com/delyee/yara_rules/blob/master/template.yar) is at the root of the repository).
Perhaps this [nonsense](https://github.com/delyee/Ese-gui), written on the knee in 2 evenings, but greatly simplifying work, if you have over100500 files, will help you in this matter.

In addition to the rules that detect certain php shells, there are Generic rules - they will allow you to quickly find potentially malicious scripts and increase the number of erased backdoors of an attacker.

It is worth noting separately that not all fussed scripts are malicious - an example of this is the directory "FalsePositive," so you should not iterate by yara output and delete all files indiscriminately.

Usage: [wiki](https://github.com/delyee/yara_rules/wiki)