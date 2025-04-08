package detector

import (
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

// SMB协议相关常量
const (
	SMB_PORT    = 445
	SMB_TIMEOUT = 5 * time.Second

	// SMB命令
	SMB_COM_NEGOTIATE          = 0x72
	SMB_COM_SESSION_SETUP_ANDX = 0x73

	// SMB标志
	SMB_FLAGS_CASE_INSENSITIVE    = 0x08
	SMB_FLAGS_CANONICALIZED_PATHS = 0x10
	SMB_FLAGS_REPLY               = 0x80

	// SMB扩展标志
	SMB_FLAGS2_UNICODE           = 0x8000
	SMB_FLAGS2_NT_STATUS         = 0x4000
	SMB_FLAGS2_EXTENDED_SECURITY = 0x0800
	SMB_FLAGS2_LONG_NAMES        = 0x0001
)

// TestOSUsingSMB 使用SMB协议检测操作系统类型
func (d *OSDetector) TestOSUsingSMB(targetIP string) map[string]bool {
	result := make(map[string]bool)

	// 最多重试3次
	for retries := 0; retries < 3; retries++ {
		// 建立TCP连接
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, SMB_PORT), SMB_TIMEOUT)
		if err != nil {
			log.Printf("SMB连接失败(尝试 %d/3): %v\n", retries+1, err)
			time.Sleep(time.Second) // 等待1秒后重试
			continue
		}
		defer conn.Close()

		// 发送SMB协商请求
		negotiateResp, err := d.sendSMBNegotiate(conn)
		if err != nil {
			log.Printf("SMB协商失败(尝试 %d/3): %v\n", retries+1, err)
			time.Sleep(time.Second) // 等待1秒后重试
			continue
		}

		// 协商成功，解析响应

		// 解析SMB响应中的操作系统信息
		osInfo := d.parseSMBOSInfo(negotiateResp)
		if osInfo != "" {
			// 成功获取操作系统信息，跳出重试循环
			log.Printf("成功获取SMB操作系统信息: %s\n", osInfo)
			// 根据SMB响应中的操作系统信息设置权重
			if strings.Contains(strings.ToLower(osInfo), "windows") {
				// 根据版本信息判断具体的Windows版本
				switch {
				case strings.Contains(osInfo, "10.0") || strings.Contains(osInfo, "11.0"):
					result["Windows 11"] = true
					result["Windows 10"] = true
					d.osWeights["Windows 11"] += 4
					d.osWeights["Windows 10"] += 3
				case strings.Contains(osInfo, "6.1"):
					result["Windows 7"] = true
					d.osWeights["Windows 7"] += 3
				case strings.Contains(osInfo, "5.1"):
					result["Windows XP"] = true
					d.osWeights["Windows XP"] += 3
				default:
					// 如果无法确定具体版本，将所有Windows版本都标记为可能
					result["Windows 11"] = true
					result["Windows 10"] = true
					result["Windows 7"] = true
					result["Windows XP"] = true
				}
			}
			// 成功完成SMB检测，返回结果
			return result
		}
	}
	// 重试次数用尽，返回空结果
	log.Println("SMB检测失败: 已达到最大重试次数")
	return result
}

// sendSMBNegotiate 发送SMB协商请求并获取响应
func (d *OSDetector) sendSMBNegotiate(conn net.Conn) ([]byte, error) {
	// 设置读写超时
	conn.SetDeadline(time.Now().Add(SMB_TIMEOUT))

	// 构造SMB协商请求包
	// 计算SMB标志和标志2的字节值
	flags := byte(SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS)
	flags2 := uint16(SMB_FLAGS2_UNICODE | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_EXTENDED_SECURITY | SMB_FLAGS2_LONG_NAMES)

	// 生成随机进程ID (16位)
	processID := uint16(rand.Uint32() & 0xFFFF)

	request := []byte{
		0xFF, 0x53, 0x4D, 0x42, // SMB协议标识
		SMB_COM_NEGOTIATE,      // 命令: SMB_COM_NEGOTIATE
		0x00, 0x00, 0x00, 0x00, // 状态
		flags,               // 标志
		byte(flags2 & 0xFF), // 标志2 (低字节)
		byte(flags2 >> 8),   // 标志2 (高字节)
		0x00, 0x00,          // 进程ID高位
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 签名
		0x00, 0x00, // 保留
		0x00, 0x00, // TreeID
		byte(processID & 0xFF), byte(processID >> 8), // 进程ID (随机，小端序)
		0x00, 0x00, // 用户ID
		0x00, 0x00, // 多路复用ID
	}

	// 发送请求
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("发送SMB请求失败: %v", err)
	}

	// 读取响应
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("读取SMB响应失败: %v", err)
	}

	return response[:n], nil
}

// parseSMBOSInfo 从SMB响应中解析操作系统信息
func (d *OSDetector) parseSMBOSInfo(response []byte) string {
	// 检查响应长度
	if len(response) < 32 {
		return ""
	}

	// 查找操作系统信息字段
	// 通常在响应的后半部分，包含类似"Windows 10 10.0"这样的字符串
	for i := 32; i < len(response)-10; i++ {
		if response[i] == 'W' && response[i+1] == 'i' && response[i+2] == 'n' {
			// 找到Windows字符串，提取操作系统信息
			osInfo := make([]byte, 0)
			for j := i; j < len(response) && response[j] != 0; j++ {
				osInfo = append(osInfo, response[j])
			}
			return string(osInfo)
		}
	}

	return ""
}
