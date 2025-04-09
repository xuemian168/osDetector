package detector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/hirochachacha/go-smb2"
)

// NTLMSSP 消息标识
var NTLMSSP_SIGNATURE = []byte("NTLMSSP\x00")

// NTLMSSP 消息类型
const (
	NTLMSSP_NEGOTIATE = 1
	NTLMSSP_CHALLENGE = 2
	NTLMSSP_AUTH      = 3
)

// NTLMSSP Version 结构
type NTLMSSPVersion struct {
	ProductMajorVersion uint8
	ProductMinorVersion uint8
	ProductBuild        uint16
	Reserved            [3]byte
	NTLMRevisionCurrent uint8
}

// smbDebugConn 用于调试SMB通信和捕获NTLMSSP消息
type smbDebugConn struct {
	net.Conn
	verbose     bool
	ntlmsspData []byte
}

func (c *smbDebugConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.verbose {
		fmt.Printf("<<< SMB READ %d bytes: %x\n", n, b[:n])
	}

	// 查找并保存NTLMSSP消息
	if n > 0 {
		if idx := bytes.Index(b[:n], NTLMSSP_SIGNATURE); idx != -1 {
			c.ntlmsspData = append(c.ntlmsspData, b[idx:n]...)
		}
	}
	return n, err
}

func (c *smbDebugConn) Write(b []byte) (int, error) {
	if c.verbose {
		fmt.Printf(">>> SMB WRITE %d bytes: %x\n", len(b), b)
	}
	return c.Conn.Write(b)
}

// 解析NTLMSSP Challenge消息中的版本信息
func parseNTLMSSPVersion(data []byte) (*NTLMSSPVersion, error) {
	if len(data) < 64 { // NTLMSSP Challenge消息至少需要64字节
		return nil, fmt.Errorf("data too short")
	}

	// 查找NTLMSSP签名
	idx := bytes.Index(data, NTLMSSP_SIGNATURE)
	if idx == -1 {
		return nil, fmt.Errorf("NTLMSSP signature not found")
	}

	// 确认是Challenge消息
	msgType := binary.LittleEndian.Uint32(data[idx+8:])
	if msgType != NTLMSSP_CHALLENGE {
		return nil, fmt.Errorf("not a challenge message")
	}

	// 版本信息通常在消息末尾
	// 这里需要根据实际捕获的数据调整偏移量
	versionOffset := idx + 48 // 这个偏移量需要根据实际数据包结构调整

	version := &NTLMSSPVersion{}
	version.ProductMajorVersion = data[versionOffset]
	version.ProductMinorVersion = data[versionOffset+1]
	version.ProductBuild = binary.LittleEndian.Uint16(data[versionOffset+2:])
	copy(version.Reserved[:], data[versionOffset+4:versionOffset+7])
	version.NTLMRevisionCurrent = data[versionOffset+7]

	return version, nil
}

func (d *OSDetector) TestOSUsingSMB(targetIP string) map[string]bool {
	resultSet := make(map[string]bool)
	for _, os := range AllOS {
		resultSet[os] = true
	}
	if d.Verbose {
		fmt.Println("[SMB test] OS options are:", d.formatOSSet(resultSet))
	}

	// 创建TCP连接
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", targetIP))
	if err != nil {
		if d.Verbose {
			fmt.Printf("[SMB test] Failed to connect: %v\n", err)
		}
		return resultSet
	}
	defer conn.Close()

	// 包装为调试连接
	debugConn := &smbDebugConn{
		Conn:        conn,
		verbose:     d.Verbose,
		ntlmsspData: make([]byte, 0),
	}

	// 创建SMB2会话
	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "Guest",
			Password: "",
			Domain:   "",
		},
	}

	// 建立SMB会话
	session, err := dialer.Dial(debugConn)
	if err != nil {
		if d.Verbose {
			fmt.Printf("[SMB test] Session error: %v\n", err)
		}
		// 即使连接失败，我们也可能已经获取到了NTLMSSP消息
	}

	// 尝试解析版本信息
	if version, err := parseNTLMSSPVersion(debugConn.ntlmsspData); err == nil {
		// 保存版本信息到检测器实例
		d.smbVersion = version

		if d.Verbose {
			fmt.Printf("[SMB test] Detected Windows version: %d.%d.%d\n",
				version.ProductMajorVersion,
				version.ProductMinorVersion,
				version.ProductBuild)
		}

		// 根据主版本号确定Windows版本
		switch version.ProductMajorVersion {
		case 10:
			resultSet = make(map[string]bool)
			resultSet["Windows 10"] = true
			resultSet["Windows 11"] = true
			d.osWeights["Windows 10"] += 3
			d.osWeights["Windows 11"] += 3

			// 根据build号进一步区分Windows 10和11
			if version.ProductBuild >= 22000 {
				d.osWeights["Windows 11"] += 2
			} else {
				d.osWeights["Windows 10"] += 2
			}
		case 6:
			switch version.ProductMinorVersion {
			case 1:
				resultSet = make(map[string]bool)
				resultSet["Windows 7"] = true
				d.osWeights["Windows 7"] += 5
			case 2, 3:
				resultSet = make(map[string]bool)
				resultSet["Windows 8"] = true
				d.osWeights["Windows 8"] += 5
			}
		case 5:
			resultSet = make(map[string]bool)
			resultSet["Windows XP"] = true
			d.osWeights["Windows XP"] += 5
		}
	}

	if session != nil {
		session.Logoff()
	}

	return resultSet
}
