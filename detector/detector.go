package detector

import (
	"fmt"
	"log"
	"net"
	"time"
)

// OSDetector 表示操作系统检测器
type OSDetector struct {
	Verbose         bool
	lastCheckedPort int            // 记录最后检查的端口号
	osWeights       map[string]int // 操作系统权重表
}

// NewOSDetector 创建一个新的操作系统检测器
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

	// 如果可以ping通，使用ICMP检测
	var icmpOSSet map[string]bool
	if isPing {
		log.Println("开始使用Ping检测操作系统类型")
		icmpOSSet = d.TestOSUsingICMP(targetIP)
		resultSet = d.intersectOSSets(resultSet, icmpOSSet)
		log.Println("Ping检测结果为：", d.formatOSSet(resultSet))

		// 增加ICMP检测结果的权重
		for os := range icmpOSSet {
			d.osWeights[os] += 2 // ICMP检测权重为2
		}

		// 特殊处理：如果ICMP检测发现Windows特征
		if d.hasWindowsICMPFeatures(targetIP) {
			d.osWeights["Windows 11"] += 2
			d.osWeights["Windows 10"] += 1
			d.osWeights["Windows 7"] += 1
			d.osWeights["Windows XP"] += 1
			log.Println("ICMP检测发现Windows特征，增加Windows系统权重")
		}
	}

	// 使用TCP检测
	var tcpOSSet map[string]bool
	log.Println("开始使用TCP端口检测操作系统类型")
	tcpOSSet = d.TestOSUsingTCP(targetIP)
	if len(tcpOSSet) > 0 {
		// 如果之前没有ICMP检测或结果集仍然较大，使用TCP检测结果
		if !isPing || len(resultSet) > 2 {
			resultSet = d.intersectOSSets(resultSet, tcpOSSet)
		}
		log.Println("TCP检测结果为：", d.formatOSSet(resultSet))

		// 增加TCP检测结果的权重
		for os := range tcpOSSet {
			d.osWeights[os] += 3 // TCP检测权重为3
		}

		// 特殊处理：如果检测到Windows特征端口
		if d.lastCheckedPort == 135 || d.lastCheckedPort == 139 || d.lastCheckedPort == 445 || d.lastCheckedPort == 3389 {
			// Windows 11和10更常见地开放这些端口，给予更高权重
			// 根据端口类型分配不同权重
			switch d.lastCheckedPort {
			case 3389: // RDP端口，Windows 11/10企业版最常用
				d.osWeights["Windows 11"] += 5
				d.osWeights["Windows 10"] += 4
				d.osWeights["Windows 7"] += 2
				d.osWeights["Windows XP"] += 1
			case 445: // SMB端口，现代Windows系统常用
				d.osWeights["Windows 11"] += 4
				d.osWeights["Windows 10"] += 3
				d.osWeights["Windows 7"] += 2
				d.osWeights["Windows XP"] += 1
			case 135: // RPC端口
				d.osWeights["Windows 11"] += 4
				d.osWeights["Windows 10"] += 3
				d.osWeights["Windows 7"] += 2
				d.osWeights["Windows XP"] += 1
			case 139: // NetBIOS端口
				d.osWeights["Windows 11"] += 3
				d.osWeights["Windows 10"] += 2
				d.osWeights["Windows 7"] += 2
				d.osWeights["Windows XP"] += 1
			}
			log.Printf("检测到Windows特征端口 %d，根据端口特征调整Windows系统权重", d.lastCheckedPort)
		}

		// 特殊处理：如果检测到Linux特征端口
		if d.lastCheckedPort == 22 || d.lastCheckedPort == 3306 {
			d.osWeights["Linux"] += 2
			d.osWeights["FreeBSD"] += 1
			d.osWeights["Centos"] += 2
			d.osWeights["Ubuntu"] += 2
			d.osWeights["Debain"] += 2
			log.Println("检测到Linux特征端口，增加Linux系统权重")
		}
	}

	// 检查是否有Windows系统，如果有可以尝试SMB检测
	hasWindows := false
	for os := range resultSet {
		if containsIgnoreCase(os, "win") {
			hasWindows = true
			log.Println("开始使用SMB端口检测操作系统类型")
			// 注意：这里简化了SMB检测，实际实现可能需要更复杂的逻辑
			// smbResult := d.TestOSUsingSMB(targetIP)
			// if smbResult != "" {
			// 	return smbResult
			// }
			break
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
		// 对于Windows系统，优先考虑Windows 11和10
		for os := range resultSet {
			weight := d.osWeights[os]
			// 如果是Windows系统，根据版本调整权重
			if containsIgnoreCase(os, "win") {
				if os == "Windows 11" {
					weight += 3 // Windows 11作为最新版本，给予最高额外权重
				} else if os == "Windows 10" {
					weight += 2 // Windows 10作为次新版本，给予较高额外权重
				}
			}
			if weight > maxWeight {
				maxWeight = weight
				finalResult = os
			}
		}

		// 如果权重相同或没有明显的权重差异，使用传统方法
		if maxWeight <= 0 {
			// 检查是否有Windows特征端口开放
			if d.lastCheckedPort == 135 || d.lastCheckedPort == 139 || d.lastCheckedPort == 445 {
				// 如果Windows特征端口开放，优先判断为Windows
				finalResult = "Windows"
			} else {
				// 否则按照常规逻辑判断
				if hasWindows {
					finalResult = "Windows"
				} else {
					finalResult = "Linux"
				}
			}
		}
	} else {
		// 如果没有结果，默认返回Windows
		finalResult = "Windows"
	}

	// 记录最终选择的操作系统及其权重
	log.Printf("最终选择的操作系统: %s (权重: %d)\n", finalResult, d.osWeights[finalResult])

	return finalResult
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
