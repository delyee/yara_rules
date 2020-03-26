/*
global rule filelimit
{
	condition:
  		filesize < 2mb

}
*/

include "./apts/index.yar"
include "./Encoders/index.yar"
include "./other/index.yar"
include "./unknown/index.yar"
include "./FalsePositive/index.yar"
include "./ioc/index.yar"
include "./generic/index.yar"
include "./soft/index.yar"
