package detector

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ProtocolDetector 协议栈检测器
type ProtocolDetector struct {
	Verbose bool
}

// TCPStackFingerprint 通过TCP协议栈特征识别操作系统
func (d *OSDetector) TCPStackFingerprint(targetIP string) map[string]bool {
	resultSet := make(map[string]bool)

	// 尝试建立TCP连接以获取协议栈特征
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80"), time.Duration(MaxRTT)*time.Second)
	if err != nil {
		return resultSet
	}
	defer conn.Close()

	// 获取TCP连接信息
	tcpConn := conn.(*net.TCPConn)

	// 获取本地地址信息
	localAddr := tcpConn.LocalAddr().(*net.TCPAddr)

	// 获取远程地址信息
	remoteAddr := tcpConn.RemoteAddr().(*net.TCPAddr)

	if d.Verbose {
		fmt.Printf("[TCP Stack] Local: %s, Remote: %s\n", localAddr, remoteAddr)
	}

	// 根据TTL值判断操作系统
	ttl := remoteAddr.IP.DefaultMask().String()
	if d.Verbose {
		fmt.Printf("[TCP Stack] TTL: %s\n", ttl)
	}

	// 根据TTL值匹配操作系统
	for os, features := range OSDB {
		if ttlFeatures, ok := features["TTL"]; ok {
			for _, ttlValue := range ttlFeatures {
				if ttl == ttlValue {
					resultSet[os] = true
				}
			}
		}
	}

	return resultSet
}

// HTTPFingerprint 通过HTTP响应头识别操作系统
func (d *OSDetector) HTTPFingerprint(targetIP string) map[string]bool {
	resultSet := make(map[string]bool)

	// 发送HTTP请求
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80"), time.Duration(MaxRTT)*time.Second)
	if err != nil {
		return resultSet
	}
	defer conn.Close()

	// 发送HTTP请求
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", targetIP)

	// 读取响应头
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return resultSet
	}

	response := string(buffer[:n])

	// 分析Server头
	if strings.Contains(response, "Server:") {
		serverHeader := strings.Split(response, "Server:")[1]
		serverHeader = strings.Split(serverHeader, "\r\n")[0]

		if d.Verbose {
			fmt.Printf("[HTTP] Server: %s\n", serverHeader)
		}

		// 根据Server头识别操作系统
		if strings.Contains(serverHeader, "Apache") {
			resultSet["Linux"] = true
			resultSet["Centos"] = true
			resultSet["Ubuntu"] = true
			resultSet["Debian"] = true
		} else if strings.Contains(serverHeader, "Microsoft-IIS") {
			resultSet["Windows"] = true
		} else if strings.Contains(serverHeader, "nginx") {
			resultSet["Linux"] = true
			resultSet["Centos"] = true
			resultSet["Ubuntu"] = true
			resultSet["Debian"] = true
		}
	}

	return resultSet
}

// SSHFingerprint 通过SSH协议识别操作系统
func (d *OSDetector) SSHFingerprint(targetIP string) map[string]bool {
	resultSet := make(map[string]bool)

	// 尝试建立SSH连接
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22"), time.Duration(MaxRTT)*time.Second)
	if err != nil {
		return resultSet
	}
	defer conn.Close()

	// 读取SSH版本信息
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return resultSet
	}

	version := string(buffer[:n])
	if d.Verbose {
		fmt.Printf("[SSH] Version: %s\n", version)
	}

	// 根据SSH版本识别操作系统
	if strings.Contains(version, "OpenSSH") {
		resultSet["Linux"] = true
		resultSet["Centos"] = true
		resultSet["Ubuntu"] = true
		resultSet["Debian"] = true
		resultSet["FreeBSD"] = true
	}

	return resultSet
}

// DNSFingerprint 通过DNS查询特征识别操作系统
func (d *OSDetector) DNSFingerprint(targetIP string) map[string]bool {
	resultSet := make(map[string]bool)

	// 发送DNS查询
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:53"), time.Duration(MaxRTT)*time.Second)
	if err != nil {
		return resultSet
	}
	defer conn.Close()

	// 构造DNS查询包
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x1234)   // ID
	query[2] = 0x01                                  // QR=0, Opcode=0
	query[3] = 0x00                                  // AA=0, TC=0, RD=1
	binary.BigEndian.PutUint16(query[4:6], 0x0001)   // QDCOUNT=1
	binary.BigEndian.PutUint16(query[6:8], 0x0000)   // ANCOUNT=0
	binary.BigEndian.PutUint16(query[8:10], 0x0000)  // NSCOUNT=0
	binary.BigEndian.PutUint16(query[10:12], 0x0000) // ARCOUNT=0

	// 发送查询
	_, err = conn.Write(query)
	if err != nil {
		return resultSet
	}

	// 读取响应
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return resultSet
	}

	// 分析DNS响应特征
	if n > 0 {
		// Windows DNS响应通常包含特定的标志位
		if buffer[2]&0x80 == 0x80 { // QR=1
			resultSet["Windows"] = true
		} else {
			resultSet["Linux"] = true
			resultSet["Centos"] = true
			resultSet["Ubuntu"] = true
			resultSet["Debian"] = true
			resultSet["FreeBSD"] = true
		}
	}

	return resultSet
}

// NTPFingerprint 通过NTP协议特征识别操作系统
func (d *OSDetector) NTPFingerprint(targetIP string) map[string]bool {
	resultSet := make(map[string]bool)

	// 发送NTP请求
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:123"), time.Duration(MaxRTT)*time.Second)
	if err != nil {
		return resultSet
	}
	defer conn.Close()

	// 构造NTP请求包
	request := make([]byte, 48)
	request[0] = 0x1b // LI=0, VN=3, Mode=3

	// 发送请求
	_, err = conn.Write(request)
	if err != nil {
		return resultSet
	}

	// 读取响应
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return resultSet
	}

	// 分析NTP响应特征
	if n > 0 {
		// Windows NTP响应通常包含特定的标志位
		if buffer[0]&0x07 == 0x04 { // Mode=4
			resultSet["Windows"] = true
		} else {
			resultSet["Linux"] = true
			resultSet["Centos"] = true
			resultSet["Ubuntu"] = true
			resultSet["Debian"] = true
			resultSet["FreeBSD"] = true
		}
	}

	return resultSet
}

// matchTCPFeatures 匹配TCP特征
func matchTCPFeatures(windowSize, mss int, options []byte, features map[interface{}][]string) bool {
	// 实现TCP特征匹配逻辑
	return false
}
