package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/xuemian/osDetector/detector"
)

func main() {
	// 设置命令行参数
	target := flag.String("t", "", "目标IP地址")
	verbose := flag.Bool("v", false, "显示详细信息")
	flag.Parse()

	// 检查必要参数
	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}

	// 初始化日志
	log.SetFlags(log.Ltime)
	log.Println("开始对目标:", *target, "进行操作系统识别")

	// 创建检测器实例
	detector := detector.NewOSDetector(*verbose)

	// 执行存活检测
	isAlive, isPing := detector.SurvivalDetect(*target)

	if !isAlive {
		log.Println("目标：", *target, "可能没有存活，检测结束")
		os.Exit(0)
	}

	// 执行操作系统检测
	result := detector.DetectOS(*target, isPing)

	// 输出结果
	fmt.Println("\n操作系统最终检测结果为：", result)
}
