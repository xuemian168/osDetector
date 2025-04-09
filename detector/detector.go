package detector

import (
	"fmt"
	"log"
	"net"
	"time"
)

type OSDetector struct {
	Verbose          bool
	lastCheckedPort  int            // 记录最后检查的端口号
	osWeights        map[string]int // 操作系统权重表
	detectionDetails []string
	smbVersion       *NTLMSSPVersion // 添加SMB版本信息字段
}

func NewOSDetector(verbose bool) *OSDetector {
	// 初始化操作系统权重表
	osWeights := make(map[string]int)
	for _, os := range AllOS {
		osWeights[os] = 0
	}
	return &OSDetector{
		Verbose:   verbose,
		osWeights: osWeights,
	}
}

// DetectOS 检测目标主机的操作系统
func (d *OSDetector) DetectOS(targetIP string, isPing bool) string {
	// 初始化结果集为所有可能的操作系统
	resultSet := make(map[string]bool)
	for _, os := range AllOS {
		resultSet[os] = true
	}

	// 重置操作系统权重表
	for _, os := range AllOS {
		d.osWeights[os] = 0
	}

	// 使用多种方法进行检测
	detectionMethods := []struct {
		name   string
		method func(*OSDetector, string) map[string]bool
	}{
		{"ICMP", (*OSDetector).TestOSUsingICMP},
		{"TCP", (*OSDetector).TestOSUsingTCP},
		{"SMB", (*OSDetector).TestOSUsingSMB},
		{"TCP Stack", (*OSDetector).TCPStackFingerprint},
		{"HTTP", (*OSDetector).HTTPFingerprint},
		{"SSH", (*OSDetector).SSHFingerprint},
		{"DNS", (*OSDetector).DNSFingerprint},
		{"NTP", (*OSDetector).NTPFingerprint},
	}

	// 执行所有检测方法
	for _, dm := range detectionMethods {
		if result := dm.method(d, targetIP); len(result) > 0 {
			resultSet = d.intersectOSSets(resultSet, result)
			if d.Verbose {
				fmt.Printf("[%s] 检测结果: %v\n", dm.name, d.formatOSSet(result))
			}
		}
	}

	// 确定最终结果
	var finalResult string
	if len(resultSet) == 1 {
		// 如果只有一个结果，直接返回
		for os := range resultSet {
			finalResult = os
			break
		}
	} else if len(resultSet) > 1 {
		// 如果有多个结果，根据权重选择最可能的操作系统
		maxWeight := -1
		for os := range resultSet {
			weight := d.osWeights[os]
			if weight > maxWeight {
				maxWeight = weight
				finalResult = os
			}
		}
	} else {
		// 如果没有结果，使用默认判断
		finalResult = d.defaultOSDetection(targetIP)
	}

	// 输出检测详情
	d.printDetectionDetails(targetIP, resultSet, finalResult)

	return finalResult
}

// getMethodName 获取方法名称
func getMethodName(method func(string) map[string]bool) string {
	switch method {
	case (*OSDetector).TestOSUsingICMP:
		return "ICMP"
	case (*OSDetector).TestOSUsingTCP:
		return "TCP"
	case (*OSDetector).TestOSUsingSMB:
		return "SMB"
	case (*OSDetector).TCPStackFingerprint:
		return "TCP Stack"
	case (*OSDetector).HTTPFingerprint:
		return "HTTP"
	case (*OSDetector).SSHFingerprint:
		return "SSH"
	case (*OSDetector).DNSFingerprint:
		return "DNS"
	case (*OSDetector).NTPFingerprint:
		return "NTP"
	default:
		return "Unknown"
	}
}

// defaultOSDetection 默认操作系统检测
func (d *OSDetector) defaultOSDetection(targetIP string) string {
	// 检查常见端口
	for _, port := range CommonTCPPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, port), time.Duration(MaxRTT)*time.Second)
		if err == nil {
			conn.Close()
			switch port {
			case 22:
				return "Linux"
			case 3389:
				return "Windows"
			case 445:
				return "Windows"
			}
		}
	}
	return "Unknown"
}

// printDetectionDetails 输出检测详情
func (d *OSDetector) printDetectionDetails(targetIP string, resultSet map[string]bool, finalResult string) {
	if !d.Verbose {
		return
	}

	fmt.Println("\n检测详情:")
	fmt.Println("----------------------------------------")
	fmt.Printf("目标IP: %s\n", targetIP)
	fmt.Printf("可能的操作系统: %v\n", d.formatOSSet(resultSet))
	fmt.Printf("最终判定: %s\n", finalResult)
	fmt.Println("----------------------------------------")
}

// hasWindowsICMPFeatures 检查ICMP响应是否具有Windows系统特征
func (d *OSDetector) hasWindowsICMPFeatures(targetIP string) bool {
	// 获取ICMP响应
	icmpReply, err := d.getICMPReply(targetIP)
	if err != nil {
		return false
	}

	// 获取IP参数
	df, ttl := d.getIPParameters(icmpReply)

	// 检查Windows特征
	// 1. TTL值接近128（Windows系统的特征）
	// 2. DF标志通常被设置（Windows系统特征）
	hasWindowsFeatures := (ttl > 64 && ttl <= 128) || df

	return hasWindowsFeatures
}

// SurvivalDetect 检测目标主机是否存活
func (d *OSDetector) SurvivalDetect(targetIP string) (bool, bool) {
	// 尝试使用ICMP检测
	isAlive := false
	isPing := false

	// 使用ICMP检测
	icmpReply, err := d.getICMPReply(targetIP)
	if err == nil && icmpReply != nil {
		isAlive = true
		isPing = true
		log.Println("目标主机响应ICMP请求，确认存活")
		return isAlive, isPing
	}

	// 如果ICMP检测失败，尝试TCP端口扫描
	for _, port := range CommonTCPPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, port), time.Duration(MaxRTT)*time.Second)
		if err == nil {
			conn.Close()
			isAlive = true
			log.Printf("目标主机端口 %d 开放，确认存活\n", port)
			break
		}
	}

	return isAlive, isPing
}
