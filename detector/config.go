package detector

// AllOS 定义所有支持的操作系统
var AllOS = []string{
	"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Windows 11",
	"Symbian", "Palm OS", "Centos", "Ubuntu", "Debain",
}

// OSDB 定义操作系统指纹数据库
var OSDB = map[string]map[interface{}][]string{
	"DF": {
		true:  {"FreeBSD", "Linux", "Windows XP", "Windows 7", "Windows 10", "Windows 11", "Centos", "Ubuntu", "Debain"},
		false: {"FreeBSD", "Symbian", "Palm OS", "Linux", "Windows XP", "Windows 7", "Windows 10", "Windows 11", "Centos", "Ubuntu"},
	},
	"TTL": {
		64:  {"Linux", "FreeBSD", "Centos", "Ubuntu"},
		128: {"Windows XP", "Windows 7", "Windows 10", "Windows 11"},
		256: {"Symbian", "Palm OS", "Cisco IOS", "Debain"},
	},
	"Win Size": {
		8192:  {"Symbian", "Windows 7", "Windows XP", "Windows 10", "Windows 11"},
		14600: {"Linux"},
		16348: {"Palm OS"},
		64240: {"Linux", "Ubuntu", "Centos"},
		65392: {"Windows 10", "Windows 11", "Windows XP", "Windows 7"},
		65535: {"FreeBSD", "Windows XP", "Windows 10", "Windows 11"},
		65550: {"FreeBSD"},
		29200: {"Centos"},
		26883: {"Debain"},
		0:     {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Windows 11", "Symbian", "Palm OS", "Centos", "Ubuntu", "Debain"},
	},
	"MSS": {
		1350: {"Palm OS"},
		1440: {"Windows XP", "Windows 7", "Windows 10", "Windows 11"},
		1460: {"Linux", "FreeBSD"},
		1200: {"Centos", "Ubuntu", "Windows 7", "Debain"},
	},
}

// CommonTCPPorts 定义常用的TCP端口
var CommonTCPPorts = []int{22, 80, 443, 135, 139, 445, 1433, 1521, 3306, 3389, 6379, 7001, 8080}

// MaxRTT 定义最大往返时间（秒）
const MaxRTT = 2

// ResendCount 定义重发次数
const ResendCount = 2
