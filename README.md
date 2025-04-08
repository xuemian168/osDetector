# OS Detector

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

## 参考资料
- https://nmap.org/nmap-fingerprinting-article.txt
-