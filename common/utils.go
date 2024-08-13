package common

import (
	"encoding/binary"
	"fmt"
	"net"
)

func IntToIP(ipInt uint32) string {
	// 将32位整数转换为4字节的切片
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ipInt)

	// 将字节切片转换为net.IP类型
	ip := net.IP(ipBytes)

	// 将net.IP类型转换为字符串
	return ip.String()
}

func Int8ToStr(arr []int8) string {
	str := ""
	for _, v := range arr {
		if v >= 0 && v <= 127 { // 确保int8值在有效的ASCII范围内
			str += string(byte(v)) // 将int8转换为byte并转换为字符串片段
		} else {
			// 处理可能的负数或其他非ASCII值，例如转换为rune并打印其Unicode编码
			str += fmt.Sprintf("\\u%04x", rune(v))
		}
	}
	return str
}

func B2S(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return string(ba)
}