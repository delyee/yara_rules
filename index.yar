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

include "./apts/index.yar"
include "./Encoders/index.yar"
include "./other/index.yar"
include "./unknown/index.yar"
//include "./FalsePositive/index.yar"
//include "./ioc/index.yar"
include "./generic/index.yar"
include "./soft/index.yar"
