package main

import "fmt"

func main() {
	// 创建一个通道，元素类型为 map[int][]map[string]float64
	channelOfMaps := make(chan map[int][]map[string]float64, 2)

	// 示例：向通道添加元素
	element1 := make(map[int][]map[string]float64)
	element1[1] = []map[string]float64{{"key1": 1.1, "key2": 2.2}, {"key3": 3.3, "key4": 4.4}, {"key3": 3.3, "key4": 4.4}}
	channelOfMaps <- element1

	element2 := make(map[int][]map[string]float64)
	element2[2] = []map[string]float64{{"key5": 5.5, "key6": 6.6}, {"key7": 7.7, "key8": 8.8}}
	channelOfMaps <- element2

	// 示例：从通道接收元素
	receivedElement1 := <-channelOfMaps
	receivedElement2 := <-channelOfMaps

	// 打印接收到的元素
	fmt.Println("Received Element 1:", receivedElement1)
	fmt.Println("Received Element 2:", receivedElement2)
}
