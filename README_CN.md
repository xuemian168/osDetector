# OS Detector

## [English Introduction](./README.md)

## 描述
这是一个基于TCP/IP栈指纹识别技术的操作系统检测工具，使用Go语言实现。该工具参考了nmap的操作系统检测原理，能够通过分析网络数据包的特征来识别目标主机运行的操作系统类型。

## 功能特点

- 支持通过ICMP协议（Ping）检测操作系统
- 支持通过TCP协议检测操作系统
- 分析IP头部特征（DF标志、TTL值）
- 分析TCP头部特征（窗口大小、MSS值）
- 支持多种操作系统的识别（Windows、Linux、FreeBSD等）
- 提供详细的检测过程日志

## 使用方法
```bash
# 安装依赖
go mod tidy

# 编译
go build -o osdetector

# 运行
./osdetector -t 192.168.1.1  # 指定目标IP地址
./osdetector -t 192.168.1.1 -v  # 显示详细信息
```

## 实现原理

该工具基于TCP/IP栈指纹识别技术，通过分析网络数据包的特征来识别目标主机运行的操作系统类型。主要使用以下技术：

1. **FIN探测** - 发送FIN包到开放端口并分析响应
2. **IP头部分析** - 分析DF（Don't Fragment）标志和TTL（Time To Live）值
3. **TCP选项分析** - 分析TCP窗口大小和MSS（Maximum Segment Size）值
4. **ICMP消息引用** - 分析ICMP错误消息的特征

不同操作系统的TCP/IP实现有细微差别，通过分析这些差别，可以推断出目标主机运行的操作系统类型。

### 检测流程

![progress](./img/progress.png)


### 运行案例
```bash
osDetector % go run main.go -t 192.168.110.71
20:37:25 开始对目标: 192.168.110.71 进行操作系统识别
20:37:31 目标主机端口 135 开放，确认存活
20:37:31 开始使用TCP端口检测操作系统类型
20:37:37 检测到Windows特征端口 135 开放，可能是Windows系统
20:37:37 找到开放端口 135，TTL=128, DF=true, WinSize=8192, MSS=1440
20:37:37 找到开放端口 135，TTL=128, DF=true, WinSize=8192, MSS=1440
20:37:37 TCP检测结果为： Windows XP, Windows 7, Windows 10
20:37:37 检测到Windows特征端口 135，根据端口特征调整Windows系统权重
20:37:37 开始使用SMB端口检测操作系统类型
20:37:37 最终选择的操作系统: Windows 10 (权重: 6)

操作系统最终检测结果为： Windows 10
```

## 参考资料
- [NMAP](https://nmap.org/nmap-fingerprinting-article.txt)
- [RFC 793](https://datatracker.ietf.org/doc/html/rfc761)
- [RFC 9293](https://www.rfc-editor.org/info/rfc9293)
- [RFC 791](https://datatracker.ietf.org/doc/html/rfc791)
- [RFC 6691](https://www.rfc-editor.org/rfc/rfc6691.html)
- [RFC 6973](https://datatracker.ietf.org/doc/html/rfc6973)