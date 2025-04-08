package detector

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"

	"golang.org/x/net/ipv4"
)

// getIPParameters 从IP头部提取参数
func (d *OSDetector) getIPParameters(ipHeader *ipv4.Header) (bool, int) {
	// 提取DF标志和TTL
	ttl := ipHeader.TTL
	df := (ipHeader.Flags & ipv4.DontFragment) != 0

	if d.Verbose {
		fmt.Printf("[IP Parameters] TTL=%d, DF=%v\n", ttl, df)
	}

	return df, ttl
}

// getOSSetFromIPParameters 根据IP参数获取可能的操作系统集合
func (d *OSDetector) getOSSetFromIPParameters(df bool, ttl int) map[string]bool {
	resultSet := make(map[string]bool)

	// 根据DF标志筛选
	dfOSSet := d.getOSSetFromDF(df)
	for os := range dfOSSet {
		resultSet[os] = true
	}

	// 根据TTL筛选
	ttlOSSet := d.getOSSetFromTTL(ttl)
	resultSet = d.intersectOSSets(resultSet, ttlOSSet)

	return resultSet
}

// getOSSetFromDF 根据DF标志获取可能的操作系统集合
func (d *OSDetector) getOSSetFromDF(df bool) map[string]bool {
	resultSet := make(map[string]bool)

	// 从数据库中获取匹配的操作系统
	if osList, ok := OSDB["DF"][df]; ok {
		for _, os := range osList {
			resultSet[os] = true
		}
	}

	return resultSet
}

// getOSSetFromTTL 根据TTL获取可能的操作系统集合
func (d *OSDetector) getOSSetFromTTL(ttl int) map[string]bool {
	resultSet := make(map[string]bool)

	// 估算初始TTL
	nextPowerOf2 := nextPowerOf2(ttl)

	// 从数据库中获取匹配的操作系统
	if osList, ok := OSDB["TTL"][nextPowerOf2]; ok {
		for _, os := range osList {
			resultSet[os] = true
		}
	} else {
		// 特殊处理：根据TTL范围推断操作系统
		if ttl > 32 && ttl <= 64 {
			// 可能是Linux/FreeBSD，初始TTL为64
			resultSet["Linux"] = true
			resultSet["FreeBSD"] = true
			resultSet["Centos"] = true
			resultSet["Ubuntu"] = true
		} else if ttl > 64 && ttl <= 128 {
			// 可能是Windows，初始TTL为128
			resultSet["Windows XP"] = true
			resultSet["Windows 7"] = true
			resultSet["Windows 10"] = true
		} else if ttl > 128 && ttl <= 255 {
			// 可能是Cisco设备或其他网络设备，初始TTL为255
			// 或者是Solaris/AIX，初始TTL为254
			resultSet["Symbian"] = true
			resultSet["Palm OS"] = true
			resultSet["Debain"] = true
		}
	}

	// 记录日志
	if d.Verbose {
		fmt.Printf("[TTL Analysis] TTL=%d, Estimated initial TTL=%d, OS options: %s\n",
			ttl, nextPowerOf2, d.formatOSSet(resultSet))
	}

	return resultSet
}

// intersectOSSets 计算两个操作系统集合的交集
func (d *OSDetector) intersectOSSets(set1, set2 map[string]bool) map[string]bool {
	result := make(map[string]bool)
	for os := range set1 {
		if set2[os] {
			result[os] = true
		}
	}
	return result
}

// formatOSSet 格式化操作系统集合为字符串
func (d *OSDetector) formatOSSet(osSet map[string]bool) string {
	var osList []string
	for os := range osSet {
		osList = append(osList, os)
	}
	return strings.Join(osList, ", ")
}

// nextPowerOf2 计算大于给定数字的最小2的幂次
func nextPowerOf2(n int) int {
	if n <= 0 {
		return 1
	}
	return 1 << (bits.Len(uint(n - 1)))
}

// isLocalIP 检查IP是否是本地网络
func isLocalIP(ip string) bool {
	// 检查是否是本地网络IP
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return true
	}
	// 检查是否是172.16.0.0/12网段
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) > 1 {
			if second, err := strconv.Atoi(parts[1]); err == nil {
				if second >= 16 && second <= 31 {
					return true
				}
			}
		}
	}
	// 检查是否是本地回环地址
	if strings.HasPrefix(ip, "127.") {
		return true
	}
	return false
}

// isLikelyWindowsIP 根据IP地址特征推断是否可能是Windows系统
func isLikelyWindowsIP(ip string) bool {
	// 这个函数是一个启发式方法，根据IP地址特征推断操作系统
	// 实际上，仅凭IP地址无法准确判断操作系统类型
	return false
}

// containsIgnoreCase 检查字符串是否包含子串（忽略大小写）
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
