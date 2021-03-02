/*
global rule filelimit
{
	condition:
  		filesize < 2mb

}
*/

/*

import "magic"

global rule zipFile
{
    condition:
        magic.type() contains "Zip"
        magic.type() contains "PHP"
        magic.type() contains "text"
}

*/
//include "./ioc/index.yar"

/*
include "./FalsePositive/index.yar"

global rule NotFalsePositive
{
    condition:
        not FalsePositive_*
}
*/


//include "./Custom/index.yar"


include "./Encoders/index.yar"
include "./other/index.yar"
include "./unknown/index.yar"
include "./soft/index.yar"
include "./Miners/index.yar"
//include "./CheckVulnerable/index.yar"
include "./generic/index.yar"
include "./apts/index.yar"

