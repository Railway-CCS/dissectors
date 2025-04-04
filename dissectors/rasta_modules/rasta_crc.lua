local my_info = 
{
    version = "1.3.0",
    description = "CRC implementation.",
    repository = "https://github.com/Railway-CCS/dissectors"
}

set_plugin_info(my_info)

local crc = {}


function crc.opt_b()
	local options = {}

	options.width = 32
    options.polynom = 0xEE5B42FD
    options.initial = 0
    options.initial_optimized = 0
    options.refin = 0
    options.refout = 0
    options.final_xor = 0
	
	--set mask and high bit
    options.crc_mask = bit32.bor((bit32.lshift((bit32.lshift(1, options.width-1) - 1), 1)), 1)
    options.crc_high_bit = bit32.lshift(1, options.width-1)


	options.table = {
  0x00000000 , 0xEE5B42FD , 0x32EDC707 , 0xDCB685FA , 0x65DB8E0E , 0x8B80CCF3 , 0x57364909 , 0xB96D0BF4
, 0xCBB71C1C , 0x25EC5EE1 , 0xF95ADB1B , 0x170199E6 , 0xAE6C9212 , 0x4037D0EF , 0x9C815515 , 0x72DA17E8
, 0x79357AC5 , 0x976E3838 , 0x4BD8BDC2 , 0xA583FF3F , 0x1CEEF4CB , 0xF2B5B636 , 0x2E0333CC , 0xC0587131
, 0xB28266D9 , 0x5CD92424 , 0x806FA1DE , 0x6E34E323 , 0xD759E8D7 , 0x3902AA2A , 0xE5B42FD0 , 0x0BEF6D2D
, 0xF26AF58A , 0x1C31B777 , 0xC087328D , 0x2EDC7070 , 0x97B17B84 , 0x79EA3979 , 0xA55CBC83 , 0x4B07FE7E
, 0x39DDE996 , 0xD786AB6B , 0x0B302E91 , 0xE56B6C6C , 0x5C066798 , 0xB25D2565 , 0x6EEBA09F , 0x80B0E262
, 0x8B5F8F4F , 0x6504CDB2 , 0xB9B24848 , 0x57E90AB5 , 0xEE840141 , 0x00DF43BC , 0xDC69C646 , 0x323284BB
, 0x40E89353 , 0xAEB3D1AE , 0x72055454 , 0x9C5E16A9 , 0x25331D5D , 0xCB685FA0 , 0x17DEDA5A , 0xF98598A7
, 0x0A8EA9E9 , 0xE4D5EB14 , 0x38636EEE , 0xD6382C13 , 0x6F5527E7 , 0x810E651A , 0x5DB8E0E0 , 0xB3E3A21D
, 0xC139B5F5 , 0x2F62F708 , 0xF3D472F2 , 0x1D8F300F , 0xA4E23BFB , 0x4AB97906 , 0x960FFCFC , 0x7854BE01
, 0x73BBD32C , 0x9DE091D1 , 0x4156142B , 0xAF0D56D6 , 0x16605D22 , 0xF83B1FDF , 0x248D9A25 , 0xCAD6D8D8
, 0xB80CCF30 , 0x56578DCD , 0x8AE10837 , 0x64BA4ACA , 0xDDD7413E , 0x338C03C3 , 0xEF3A8639 , 0x0161C4C4
, 0xF8E45C63 , 0x16BF1E9E , 0xCA099B64 , 0x2452D999 , 0x9D3FD26D , 0x73649090 , 0xAFD2156A , 0x41895797
, 0x3353407F , 0xDD080282 , 0x01BE8778 , 0xEFE5C585 , 0x5688CE71 , 0xB8D38C8C , 0x64650976 , 0x8A3E4B8B
, 0x81D126A6 , 0x6F8A645B , 0xB33CE1A1 , 0x5D67A35C , 0xE40AA8A8 , 0x0A51EA55 , 0xD6E76FAF , 0x38BC2D52
, 0x4A663ABA , 0xA43D7847 , 0x788BFDBD , 0x96D0BF40 , 0x2FBDB4B4 , 0xC1E6F649 , 0x1D5073B3 , 0xF30B314E
, 0x151D53D2 , 0xFB46112F , 0x27F094D5 , 0xC9ABD628 , 0x70C6DDDC , 0x9E9D9F21 , 0x422B1ADB , 0xAC705826
, 0xDEAA4FCE , 0x30F10D33 , 0xEC4788C9 , 0x021CCA34 , 0xBB71C1C0 , 0x552A833D , 0x899C06C7 , 0x67C7443A
, 0x6C282917 , 0x82736BEA , 0x5EC5EE10 , 0xB09EACED , 0x09F3A719 , 0xE7A8E5E4 , 0x3B1E601E , 0xD54522E3
, 0xA79F350B , 0x49C477F6 , 0x9572F20C , 0x7B29B0F1 , 0xC244BB05 , 0x2C1FF9F8 , 0xF0A97C02 , 0x1EF23EFF
, 0xE777A658 , 0x092CE4A5 , 0xD59A615F , 0x3BC123A2 , 0x82AC2856 , 0x6CF76AAB , 0xB041EF51 , 0x5E1AADAC
, 0x2CC0BA44 , 0xC29BF8B9 , 0x1E2D7D43 , 0xF0763FBE , 0x491B344A , 0xA74076B7 , 0x7BF6F34D , 0x95ADB1B0
, 0x9E42DC9D , 0x70199E60 , 0xACAF1B9A , 0x42F45967 , 0xFB995293 , 0x15C2106E , 0xC9749594 , 0x272FD769
, 0x55F5C081 , 0xBBAE827C , 0x67180786 , 0x8943457B , 0x302E4E8F , 0xDE750C72 , 0x02C38988 , 0xEC98CB75
, 0x1F93FA3B , 0xF1C8B8C6 , 0x2D7E3D3C , 0xC3257FC1 , 0x7A487435 , 0x941336C8 , 0x48A5B332 , 0xA6FEF1CF
, 0xD424E627 , 0x3A7FA4DA , 0xE6C92120 , 0x089263DD , 0xB1FF6829 , 0x5FA42AD4 , 0x8312AF2E , 0x6D49EDD3
, 0x66A680FE , 0x88FDC203 , 0x544B47F9 , 0xBA100504 , 0x037D0EF0 , 0xED264C0D , 0x3190C9F7 , 0xDFCB8B0A
, 0xAD119CE2 , 0x434ADE1F , 0x9FFC5BE5 , 0x71A71918 , 0xC8CA12EC , 0x26915011 , 0xFA27D5EB , 0x147C9716
, 0xEDF90FB1 , 0x03A24D4C , 0xDF14C8B6 , 0x314F8A4B , 0x882281BF , 0x6679C342 , 0xBACF46B8 , 0x54940445
, 0x264E13AD , 0xC8155150 , 0x14A3D4AA , 0xFAF89657 , 0x43959DA3 , 0xADCEDF5E , 0x71785AA4 , 0x9F231859
, 0x94CC7574 , 0x7A973789 , 0xA621B273 , 0x487AF08E , 0xF117FB7A , 0x1F4CB987 , 0xC3FA3C7D , 0x2DA17E80
, 0x5F7B6968 , 0xB1202B95 , 0x6D96AE6F , 0x83CDEC92 , 0x3AA0E766 , 0xD4FBA59B , 0x084D2061 , 0xE616629C
}

    return options
end

function crc.opt_c()
	local options = {}
	
	options.width = 32
    options.polynom = 0x1EDC6F41
    options.initial = 0x2A26F826
    options.initial_optimized = 0xFFFFFFFF
    options.refin = 1
    options.refout = 1
    options.final_xor = 0xFFFFFFFF

    --set mask and high bit
    options.crc_mask = bit32.bor((bit32.lshift((bit32.lshift(1, options.width-1) - 1), 1)), 1)
    options.crc_high_bit = bit32.lshift(1, options.width-1)

	
	options.table = {
  0x00000000 , 0x1EDC6F41 , 0x3DB8DE82 , 0x2364B1C3 , 0x7B71BD04 , 0x65ADD245 , 0x46C96386 , 0x58150CC7
, 0xF6E37A08 , 0xE83F1549 , 0xCB5BA48A , 0xD587CBCB , 0x8D92C70C , 0x934EA84D , 0xB02A198E , 0xAEF676CF
, 0xF31A9B51 , 0xEDC6F410 , 0xCEA245D3 , 0xD07E2A92 , 0x886B2655 , 0x96B74914 , 0xB5D3F8D7 , 0xAB0F9796
, 0x05F9E159 , 0x1B258E18 , 0x38413FDB , 0x269D509A , 0x7E885C5D , 0x6054331C , 0x433082DF , 0x5DECED9E
, 0xF8E959E3 , 0xE63536A2 , 0xC5518761 , 0xDB8DE820 , 0x8398E4E7 , 0x9D448BA6 , 0xBE203A65 , 0xA0FC5524
, 0x0E0A23EB , 0x10D64CAA , 0x33B2FD69 , 0x2D6E9228 , 0x757B9EEF , 0x6BA7F1AE , 0x48C3406D , 0x561F2F2C
, 0x0BF3C2B2 , 0x152FADF3 , 0x364B1C30 , 0x28977371 , 0x70827FB6 , 0x6E5E10F7 , 0x4D3AA134 , 0x53E6CE75
, 0xFD10B8BA , 0xE3CCD7FB , 0xC0A86638 , 0xDE740979 , 0x866105BE , 0x98BD6AFF , 0xBBD9DB3C , 0xA505B47D
, 0xEF0EDC87 , 0xF1D2B3C6 , 0xD2B60205 , 0xCC6A6D44 , 0x947F6183 , 0x8AA30EC2 , 0xA9C7BF01 , 0xB71BD040
, 0x19EDA68F , 0x0731C9CE , 0x2455780D , 0x3A89174C , 0x629C1B8B , 0x7C4074CA , 0x5F24C509 , 0x41F8AA48
, 0x1C1447D6 , 0x02C82897 , 0x21AC9954 , 0x3F70F615 , 0x6765FAD2 , 0x79B99593 , 0x5ADD2450 , 0x44014B11
, 0xEAF73DDE , 0xF42B529F , 0xD74FE35C , 0xC9938C1D , 0x918680DA , 0x8F5AEF9B , 0xAC3E5E58 , 0xB2E23119
, 0x17E78564 , 0x093BEA25 , 0x2A5F5BE6 , 0x348334A7 , 0x6C963860 , 0x724A5721 , 0x512EE6E2 , 0x4FF289A3
, 0xE104FF6C , 0xFFD8902D , 0xDCBC21EE , 0xC2604EAF , 0x9A754268 , 0x84A92D29 , 0xA7CD9CEA , 0xB911F3AB
, 0xE4FD1E35 , 0xFA217174 , 0xD945C0B7 , 0xC799AFF6 , 0x9F8CA331 , 0x8150CC70 , 0xA2347DB3 , 0xBCE812F2
, 0x121E643D , 0x0CC20B7C , 0x2FA6BABF , 0x317AD5FE , 0x696FD939 , 0x77B3B678 , 0x54D707BB , 0x4A0B68FA
, 0xC0C1D64F , 0xDE1DB90E , 0xFD7908CD , 0xE3A5678C , 0xBBB06B4B , 0xA56C040A , 0x8608B5C9 , 0x98D4DA88
, 0x3622AC47 , 0x28FEC306 , 0x0B9A72C5 , 0x15461D84 , 0x4D531143 , 0x538F7E02 , 0x70EBCFC1 , 0x6E37A080
, 0x33DB4D1E , 0x2D07225F , 0x0E63939C , 0x10BFFCDD , 0x48AAF01A , 0x56769F5B , 0x75122E98 , 0x6BCE41D9
, 0xC5383716 , 0xDBE45857 , 0xF880E994 , 0xE65C86D5 , 0xBE498A12 , 0xA095E553 , 0x83F15490 , 0x9D2D3BD1
, 0x38288FAC , 0x26F4E0ED , 0x0590512E , 0x1B4C3E6F , 0x435932A8 , 0x5D855DE9 , 0x7EE1EC2A , 0x603D836B
, 0xCECBF5A4 , 0xD0179AE5 , 0xF3732B26 , 0xEDAF4467 , 0xB5BA48A0 , 0xAB6627E1 , 0x88029622 , 0x96DEF963
, 0xCB3214FD , 0xD5EE7BBC , 0xF68ACA7F , 0xE856A53E , 0xB043A9F9 , 0xAE9FC6B8 , 0x8DFB777B , 0x9327183A
, 0x3DD16EF5 , 0x230D01B4 , 0x0069B077 , 0x1EB5DF36 , 0x46A0D3F1 , 0x587CBCB0 , 0x7B180D73 , 0x65C46232
, 0x2FCF0AC8 , 0x31136589 , 0x1277D44A , 0x0CABBB0B , 0x54BEB7CC , 0x4A62D88D , 0x6906694E , 0x77DA060F
, 0xD92C70C0 , 0xC7F01F81 , 0xE494AE42 , 0xFA48C103 , 0xA25DCDC4 , 0xBC81A285 , 0x9FE51346 , 0x81397C07
, 0xDCD59199 , 0xC209FED8 , 0xE16D4F1B , 0xFFB1205A , 0xA7A42C9D , 0xB97843DC , 0x9A1CF21F , 0x84C09D5E
, 0x2A36EB91 , 0x34EA84D0 , 0x178E3513 , 0x09525A52 , 0x51475695 , 0x4F9B39D4 , 0x6CFF8817 , 0x7223E756
, 0xD726532B , 0xC9FA3C6A , 0xEA9E8DA9 , 0xF442E2E8 , 0xAC57EE2F , 0xB28B816E , 0x91EF30AD , 0x8F335FEC
, 0x21C52923 , 0x3F194662 , 0x1C7DF7A1 , 0x02A198E0 , 0x5AB49427 , 0x4468FB66 , 0x670C4AA5 , 0x79D025E4
, 0x243CC87A , 0x3AE0A73B , 0x198416F8 , 0x075879B9 , 0x5F4D757E , 0x41911A3F , 0x62F5ABFC , 0x7C29C4BD
, 0xD2DFB272 , 0xCC03DD33 , 0xEF676CF0 , 0xF1BB03B1 , 0xA9AE0F76 , 0xB7726037 , 0x9416D1F4 , 0x8ACABEB5
}

    return options
end

function crc.opt_d()
	local options = {}
	
	options.width = 16
    options.polynom = 0x1021
    options.initial = 0
    options.initial_optimized = 0
    options.refin = 1
    options.refout = 1
    options.final_xor = 0

    --set mask and high bit
    options.crc_mask = bit32.bor((bit32.lshift((bit32.lshift(1, options.width-1) - 1), 1)), 1)
    options.crc_high_bit = bit32.lshift(1, options.width-1)


	options.table = {
  0x0000 , 0x1021 , 0x2042 , 0x3063 , 0x4084 , 0x50A5 , 0x60C6 , 0x70E7 , 0x8108 , 0x9129 , 0xA14A , 0xB16B , 0xC18C , 0xD1AD , 0xE1CE , 0xF1EF
, 0x1231 , 0x0210 , 0x3273 , 0x2252 , 0x52B5 , 0x4294 , 0x72F7 , 0x62D6 , 0x9339 , 0x8318 , 0xB37B , 0xA35A , 0xD3BD , 0xC39C , 0xF3FF , 0xE3DE
, 0x2462 , 0x3443 , 0x0420 , 0x1401 , 0x64E6 , 0x74C7 , 0x44A4 , 0x5485 , 0xA56A , 0xB54B , 0x8528 , 0x9509 , 0xE5EE , 0xF5CF , 0xC5AC , 0xD58D
, 0x3653 , 0x2672 , 0x1611 , 0x0630 , 0x76D7 , 0x66F6 , 0x5695 , 0x46B4 , 0xB75B , 0xA77A , 0x9719 , 0x8738 , 0xF7DF , 0xE7FE , 0xD79D , 0xC7BC
, 0x48C4 , 0x58E5 , 0x6886 , 0x78A7 , 0x0840 , 0x1861 , 0x2802 , 0x3823 , 0xC9CC , 0xD9ED , 0xE98E , 0xF9AF , 0x8948 , 0x9969 , 0xA90A , 0xB92B
, 0x5AF5 , 0x4AD4 , 0x7AB7 , 0x6A96 , 0x1A71 , 0x0A50 , 0x3A33 , 0x2A12 , 0xDBFD , 0xCBDC , 0xFBBF , 0xEB9E , 0x9B79 , 0x8B58 , 0xBB3B , 0xAB1A
, 0x6CA6 , 0x7C87 , 0x4CE4 , 0x5CC5 , 0x2C22 , 0x3C03 , 0x0C60 , 0x1C41 , 0xEDAE , 0xFD8F , 0xCDEC , 0xDDCD , 0xAD2A , 0xBD0B , 0x8D68 , 0x9D49
, 0x7E97 , 0x6EB6 , 0x5ED5 , 0x4EF4 , 0x3E13 , 0x2E32 , 0x1E51 , 0x0E70 , 0xFF9F , 0xEFBE , 0xDFDD , 0xCFFC , 0xBF1B , 0xAF3A , 0x9F59 , 0x8F78
, 0x9188 , 0x81A9 , 0xB1CA , 0xA1EB , 0xD10C , 0xC12D , 0xF14E , 0xE16F , 0x1080 , 0x00A1 , 0x30C2 , 0x20E3 , 0x5004 , 0x4025 , 0x7046 , 0x6067
, 0x83B9 , 0x9398 , 0xA3FB , 0xB3DA , 0xC33D , 0xD31C , 0xE37F , 0xF35E , 0x02B1 , 0x1290 , 0x22F3 , 0x32D2 , 0x4235 , 0x5214 , 0x6277 , 0x7256
, 0xB5EA , 0xA5CB , 0x95A8 , 0x8589 , 0xF56E , 0xE54F , 0xD52C , 0xC50D , 0x34E2 , 0x24C3 , 0x14A0 , 0x0481 , 0x7466 , 0x6447 , 0x5424 , 0x4405
, 0xA7DB , 0xB7FA , 0x8799 , 0x97B8 , 0xE75F , 0xF77E , 0xC71D , 0xD73C , 0x26D3 , 0x36F2 , 0x0691 , 0x16B0 , 0x6657 , 0x7676 , 0x4615 , 0x5634
, 0xD94C , 0xC96D , 0xF90E , 0xE92F , 0x99C8 , 0x89E9 , 0xB98A , 0xA9AB , 0x5844 , 0x4865 , 0x7806 , 0x6827 , 0x18C0 , 0x08E1 , 0x3882 , 0x28A3
, 0xCB7D , 0xDB5C , 0xEB3F , 0xFB1E , 0x8BF9 , 0x9BD8 , 0xABBB , 0xBB9A , 0x4A75 , 0x5A54 , 0x6A37 , 0x7A16 , 0x0AF1 , 0x1AD0 , 0x2AB3 , 0x3A92
, 0xFD2E , 0xED0F , 0xDD6C , 0xCD4D , 0xBDAA , 0xAD8B , 0x9DE8 , 0x8DC9 , 0x7C26 , 0x6C07 , 0x5C64 , 0x4C45 , 0x3CA2 , 0x2C83 , 0x1CE0 , 0x0CC1
, 0xEF1F , 0xFF3E , 0xCF5D , 0xDF7C , 0xAF9B , 0xBFBA , 0x8FD9 , 0x9FF8 , 0x6E17 , 0x7E36 , 0x4E55 , 0x5E74 , 0x2E93 , 0x3EB2 , 0x0ED1 , 0x1EF0
}

    return options

end

function crc.opt_e()
	local options = {}
	
	options.width = 16
    options.polynom = 0x8005
    options.initial = 0
    options.initial_optimized = 0
    options.refin = 1
    options.refout = 1

    --set mask and high bit
    options.crc_mask = bit32.bor((bit32.lshift((bit32.lshift(1, options.width-1) - 1), 1)), 1)
    options.crc_high_bit = bit32.lshift(1, options.width-1)


	options.table = {
  0x0000 , 0x8005 , 0x800F , 0x000A , 0x801B , 0x001E , 0x0014 , 0x8011 , 0x8033 , 0x0036 , 0x003C , 0x8039 , 0x0028 , 0x802D , 0x8027 , 0x0022
, 0x8063 , 0x0066 , 0x006C , 0x8069 , 0x0078 , 0x807D , 0x8077 , 0x0072 , 0x0050 , 0x8055 , 0x805F , 0x005A , 0x804B , 0x004E , 0x0044 , 0x8041
, 0x80C3 , 0x00C6 , 0x00CC , 0x80C9 , 0x00D8 , 0x80DD , 0x80D7 , 0x00D2 , 0x00F0 , 0x80F5 , 0x80FF , 0x00FA , 0x80EB , 0x00EE , 0x00E4 , 0x80E1
, 0x00A0 , 0x80A5 , 0x80AF , 0x00AA , 0x80BB , 0x00BE , 0x00B4 , 0x80B1 , 0x8093 , 0x0096 , 0x009C , 0x8099 , 0x0088 , 0x808D , 0x8087 , 0x0082
, 0x8183 , 0x0186 , 0x018C , 0x8189 , 0x0198 , 0x819D , 0x8197 , 0x0192 , 0x01B0 , 0x81B5 , 0x81BF , 0x01BA , 0x81AB , 0x01AE , 0x01A4 , 0x81A1
, 0x01E0 , 0x81E5 , 0x81EF , 0x01EA , 0x81FB , 0x01FE , 0x01F4 , 0x81F1 , 0x81D3 , 0x01D6 , 0x01DC , 0x81D9 , 0x01C8 , 0x81CD , 0x81C7 , 0x01C2
, 0x0140 , 0x8145 , 0x814F , 0x014A , 0x815B , 0x015E , 0x0154 , 0x8151 , 0x8173 , 0x0176 , 0x017C , 0x8179 , 0x0168 , 0x816D , 0x8167 , 0x0162
, 0x8123 , 0x0126 , 0x012C , 0x8129 , 0x0138 , 0x813D , 0x8137 , 0x0132 , 0x0110 , 0x8115 , 0x811F , 0x011A , 0x810B , 0x010E , 0x0104 , 0x8101
, 0x8303 , 0x0306 , 0x030C , 0x8309 , 0x0318 , 0x831D , 0x8317 , 0x0312 , 0x0330 , 0x8335 , 0x833F , 0x033A , 0x832B , 0x032E , 0x0324 , 0x8321
, 0x0360 , 0x8365 , 0x836F , 0x036A , 0x837B , 0x037E , 0x0374 , 0x8371 , 0x8353 , 0x0356 , 0x035C , 0x8359 , 0x0348 , 0x834D , 0x8347 , 0x0342
, 0x03C0 , 0x83C5 , 0x83CF , 0x03CA , 0x83DB , 0x03DE , 0x03D4 , 0x83D1 , 0x83F3 , 0x03F6 , 0x03FC , 0x83F9 , 0x03E8 , 0x83ED , 0x83E7 , 0x03E2
, 0x83A3 , 0x03A6 , 0x03AC , 0x83A9 , 0x03B8 , 0x83BD , 0x83B7 , 0x03B2 , 0x0390 , 0x8395 , 0x839F , 0x039A , 0x838B , 0x038E , 0x0384 , 0x8381
, 0x0280 , 0x8285 , 0x828F , 0x028A , 0x829B , 0x029E , 0x0294 , 0x8291 , 0x82B3 , 0x02B6 , 0x02BC , 0x82B9 , 0x02A8 , 0x82AD , 0x82A7 , 0x02A2
, 0x82E3 , 0x02E6 , 0x02EC , 0x82E9 , 0x02F8 , 0x82FD , 0x82F7 , 0x02F2 , 0x02D0 , 0x82D5 , 0x82DF , 0x02DA , 0x82CB , 0x02CE , 0x02C4 , 0x82C1
, 0x8243 , 0x0246 , 0x024C , 0x8249 , 0x0258 , 0x825D , 0x8257 , 0x0252 , 0x0270 , 0x8275 , 0x827F , 0x027A , 0x826B , 0x026E , 0x0264 , 0x8261
, 0x0220 , 0x8225 , 0x822F , 0x022A , 0x823B , 0x023E , 0x0234 , 0x8231 , 0x8213 , 0x0216 , 0x021C , 0x8219 , 0x0208 , 0x820D , 0x8207 , 0x0202
}

    return options
end

function crc.reflect(crc_in, n)
	local j = 1
	local crc_out = 0

  local i = bit32.lshift(1, n-1)
	for i=bit32.lshift(1, n-1), i, bit32.rshift(i, 1) do
		if bit32.band(crc_in, i) == 1 then
			crc_out = bit32.bor(crc_out, j)
		end
		
		j = bit32.lshift(j, 1)
	end
end

function crc.calculate(options, bytes)
	local crc_i = options.initial_optimized
	
	if options.refin == 1 then
		crc_i = crc.reflect(crc_i, options.width)
	end

	if options.refin == 0 then
		for i=1, string.len(bytes) do
			local byte_at_i = string.byte(bytes, i, i)
			local index = bit32.bxor(bit32.band(bit32.rshift(crc_i, options.width-8), 0xff), byte_at_i)
			crc_i = bit32.bxor(bit32.lshift(crc_i, 8), options.table[index+1])
		end
	else
		for i=1, string.len(bytes) do
			local byte_at_i = string.byte(bytes, i, i)
			crc_i = bit32.bxor(bit32.rshift(crc_i, 8), options.table[bit32.bxor(bit32.band(crc_i, 0xff), byte_at_i) + 1])
		end
	end

	if bit32.bxor(options.refout, options.refin) == 1 then
		crc_i = crc.reflect(crc_i, options.width)
	end

	crc_i = bit32.bxor(crc_i, options.final_xor)
	crc_i = bit32.band(crc_i, options.crc_mask)

	return crc_i
end

return crc
