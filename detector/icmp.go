package detector

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestOSUsingICMP 使用ICMP协议测试操作系统
func (d *OSDetector) TestOSUsingICMP(targetIP string) map[string]bool {
	resultSet := make(map[string]bool)
	for _, os := range AllOS {
		resultSet[os] = true
	}

	if d.Verbose {
		fmt.Println("[ICMP test] OS options are:", d.formatOSSet(resultSet))
	}

	// 发送ICMP请求并获取回复
	icmpReply, err := d.getICMPReply(targetIP)
	if err != nil {
		log.Println("目的主机没有响应icmp请求。无法使用icmp缩小操作系统选项。")
		return resultSet
	}

	// 分析IP层
	df, ttl := d.getIPParameters(icmpReply)
	ipLayerOSSet := d.getOSSetFromIPParameters(df, ttl)
	resultSet = d.intersectOSSets(resultSet, ipLayerOSSet)

	if d.Verbose {
		fmt.Println("[ICMP test] IP layer OS options are:", d.formatOSSet(resultSet))
	}

	// 检查是否有Windows特征
	hasWindowsFeatures := false

	// 检查TTL是否接近128（Windows系统的特征）
	if ttl > 64 && ttl <= 128 {
		hasWindowsFeatures = true
		log.Println("ICMP响应的TTL值接近128，可能是Windows系统")
	}

	// 检查DF标志（Windows系统通常设置DF标志）
	if df {
		hasWindowsFeatures = true
		log.Println("ICMP响应设置了DF标志，可能是Windows系统")
	}

	// 如果有Windows特征，增加Windows系统的权重
	if hasWindowsFeatures {
		// 检查结果集中是否包含Windows系统
		hasWindows := false
		for os := range resultSet {
			if containsIgnoreCase(os, "win") {
				hasWindows = true
				break
			}
		}

		// 如果结果集中包含Windows系统，根据特征调整权重
		if hasWindows {
			// 根据TTL和DF标志的组合特征分配权重
			if ttl > 64 && ttl <= 128 && df {
				// Windows 11/10的典型特征：TTL接近128且设置DF标志
				d.osWeights["Windows 11"] += 4
				d.osWeights["Windows 10"] += 3
				d.osWeights["Windows 7"] += 2
				d.osWeights["Windows XP"] += 1
				log.Println("ICMP检测发现典型Windows特征(TTL接近128且DF标志)，Windows 11/10获得更高权重")
			} else if ttl > 64 && ttl <= 128 {
				// 仅TTL特征
				d.osWeights["Windows 11"] += 3
				d.osWeights["Windows 10"] += 2
				d.osWeights["Windows 7"] += 2
				d.osWeights["Windows XP"] += 1
				log.Println("ICMP检测发现Windows TTL特征，增加Windows系统权重")
			} else if df {
				// 仅DF标志特征
				d.osWeights["Windows 11"] += 3
				d.osWeights["Windows 10"] += 2
				d.osWeights["Windows 7"] += 1
				d.osWeights["Windows XP"] += 1
				log.Println("ICMP检测发现Windows DF标志特征，增加Windows系统权重")
			}
		}
	}

	if d.Verbose {
		fmt.Println("[ICMP test] Final OS options are:", d.formatOSSet(resultSet))
	}

	return resultSet
}

// getICMPReply 发送ICMP请求并获取回复
func (d *OSDetector) getICMPReply(targetIP string) (*ipv4.Header, error) {
	// 创建ICMP连接
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// 设置超时
	c.SetDeadline(time.Now().Add(time.Duration(MaxRTT) * time.Second))

	// 创建ICMP消息
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	// 序列化ICMP消息
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}

	// 解析目标IP
	dstAddr, err := net.ResolveIPAddr("ip4", targetIP)
	if err != nil {
		return nil, err
	}

	// 发送ICMP消息
	_, err = c.WriteTo(msgBytes, dstAddr)
	if err != nil {
		return nil, err
	}

	// 接收回复
	reply := make([]byte, 1500)
	n, peer, err := c.ReadFrom(reply)
	if err != nil {
		return nil, err
	}

	// 解析回复
	parsedMsg, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return nil, err
	}

	// 检查是否是Echo回复
	if parsedMsg.Type != ipv4.ICMPTypeEchoReply {
		return nil, fmt.Errorf("got %v, want %v", parsedMsg.Type, ipv4.ICMPTypeEchoReply)
	}

	// 获取TTL值
	var ttl int

	// 尝试从回复中推断TTL
	ipAddr := peer.(*net.IPAddr).IP.String()
	isLocalNetwork := isLocalIP(ipAddr)

	if isLocalNetwork {
		// 本地网络，TTL可能接近原始值
		if parsedMsg.Body != nil {
			if echo, ok := parsedMsg.Body.(*icmp.Echo); ok {
				if echo.Seq == 1 && len(echo.Data) > 0 {
					if string(echo.Data) == "HELLO-R-U-THERE" {
						ttl = 128 // 可能是Windows系统
					} else {
						ttl = 64 // 可能是Linux/Unix系统
					}
				}
			}
		}
	} else {
		// 远程网络，根据IP地址范围推断
		if isLikelyWindowsIP(ipAddr) {
			ttl = 128
		} else {
			ttl = 64
		}
	}

	// 创建IP头部
	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      ttl,
		Protocol: 1, // ICMP
		Dst:      net.ParseIP(targetIP),
		Src:      peer.(*net.IPAddr).IP,
		// 设置DF标志
		Flags: ipv4.DontFragment,
	}

	return ipHeader, nil
}
