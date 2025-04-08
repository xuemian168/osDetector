package detector

import (
	"fmt"
	"log"
	"net"
	"time"
)

// TestOSUsingTCP 使用TCP协议测试操作系统
func (d *OSDetector) TestOSUsingTCP(targetIP string) map[string]bool {
	resultSet := make(map[string]bool)
	for _, os := range AllOS {
		resultSet[os] = true
	}

	if d.Verbose {
		fmt.Println("[TCP test] OS options are:", d.formatOSSet(resultSet))
	}

	// 尝试连接TCP端口并分析响应
	port, ttl, df, winSize, mss, err := d.getTCPParameters(targetIP)
	if err != nil {
		log.Println("找不到打开的TCP端口。无法使用TCP缩小操作系统选项。")
		return resultSet
	}

	log.Printf("找到开放端口 %d，TTL=%d, DF=%v, WinSize=%d, MSS=%d\n", port, ttl, df, winSize, mss)

	// 分析IP层
	ipLayerOSSet := d.getOSSetFromIPParameters(df, ttl)
	resultSet = d.intersectOSSets(resultSet, ipLayerOSSet)

	if d.Verbose {
		fmt.Println("[TCP test] IP layer OS options are:", d.formatOSSet(resultSet))
	}

	// 分析TCP层
	tcpLayerOSSet := d.getOSSetFromTCPParameters(winSize, mss)
	resultSet = d.intersectOSSets(resultSet, tcpLayerOSSet)

	if d.Verbose {
		fmt.Println("[TCP test] TCP layer OS options are:", d.formatOSSet(resultSet))
	}

	return resultSet
}

// getTCPParameters 获取TCP连接的参数
func (d *OSDetector) getTCPParameters(targetIP string) (int, int, bool, int, int, error) {
	// 尝试连接常用TCP端口
	for _, port := range CommonTCPPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, port), time.Duration(MaxRTT)*time.Second)
		if err == nil {
			// 成功连接，获取TCP参数
			tcpConn, ok := conn.(*net.TCPConn)
			if ok {
				// 设置TCP选项，尝试获取更多信息
				tcpConn.SetNoDelay(true)
			}

			// 关闭连接
			conn.Close()

			// 保存最后检查的端口
			d.lastCheckedPort = port

			// 默认参数 - 假设是Linux/FreeBSD
			ttl := 64        // Linux/FreeBSD默认TTL
			df := true       // 默认DF标志
			winSize := 65535 // 默认窗口大小
			mss := 1460      // 默认MSS

			// 根据端口特征判断操作系统
			// Windows特征端口检测
			isWindowsPort := false
			if port == 135 || port == 139 || port == 445 || port == 3389 {
				isWindowsPort = true
				// Windows系统的典型特征
				ttl = 128      // Windows默认TTL
				winSize = 8192 // 常见Windows窗口大小
				mss = 1440     // Windows常见MSS
				log.Println("检测到Windows特征端口", port, "开放，可能是Windows系统")
			}

			// 根据端口号进行更细致的判断
			switch port {
			case 22: // SSH
				// SSH通常在Unix/Linux系统上运行
				if !isWindowsPort {
					ttl = 64
					winSize = 65535
					mss = 1460
					log.Println("检测到SSH端口开放，可能是Linux/Unix系统")
				}
			case 80, 443: // HTTP/HTTPS
				// Web服务器可能在任何系统上运行，需要进一步分析
				if !isWindowsPort {
					// 默认保持Linux/FreeBSD参数
				}
			case 3306: // MySQL
				// MySQL通常在Unix/Linux系统上运行
				if !isWindowsPort {
					ttl = 64
					log.Println("检测到MySQL端口开放，可能是Linux/Unix系统")
				}
			}

			// 记录检测到的参数
			log.Printf("找到开放端口 %d，TTL=%d, DF=%v, WinSize=%d, MSS=%d\n", port, ttl, df, winSize, mss)

			return port, ttl, df, winSize, mss, nil
		}
	}

	return 0, 0, false, 0, 0, fmt.Errorf("no open TCP ports found")
}

// getOSSetFromTCPParameters 根据TCP参数获取可能的操作系统集合
func (d *OSDetector) getOSSetFromTCPParameters(winSize, mss int) map[string]bool {
	resultSet := make(map[string]bool)

	// 根据窗口大小判断
	if winSize == 8192 {
		// Windows典型窗口大小
		resultSet["Windows XP"] = true
		resultSet["Windows 7"] = true
		resultSet["Windows 10"] = true
	} else if winSize == 65535 {
		// Linux/Unix典型窗口大小
		resultSet["Linux"] = true
		resultSet["FreeBSD"] = true
		resultSet["Centos"] = true
		resultSet["Ubuntu"] = true
		resultSet["Debain"] = true
	}

	// 根据MSS判断
	if mss == 1440 {
		// Windows典型MSS
		resultSet["Windows XP"] = true
		resultSet["Windows 7"] = true
		resultSet["Windows 10"] = true
	} else if mss == 1460 {
		// Linux/Unix典型MSS
		resultSet["Linux"] = true
		resultSet["FreeBSD"] = true
		resultSet["Centos"] = true
		resultSet["Ubuntu"] = true
		resultSet["Debain"] = true
	}

	return resultSet
}
