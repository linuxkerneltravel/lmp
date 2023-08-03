package connect_to_ecliserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
)

type RequesetBody struct {
	ID int `json:"id"`
}

func Get_Running_Program(address string) map[string]int {
	resp, err := http.Get(address)
	if err != nil {
		log.Printf("Get running list fialed:%v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Get request return non-OK status:", resp.StatusCode)
		return nil
	}
	var data map[string][]map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Println("fail to decode JSON data:", err)
		return nil
	}
	result := make(map[string]int)
	// 将get方法获取的json数据转换成需要的形式:{"bpf_name":id}
	for _, v := range data {
		for _, kv := range v {
			id, err := strconv.Atoi(kv["id"])
			if err != nil {
				log.Println("failed to convert id to int", err)
				return nil
			}
			result[kv["name"]] = id
		}
	}
	return result
}

func Get_Data(address string, name string, specific map[string]int) {
	requestbody := RequesetBody{
		ID: specific[name],
	}
	jsonData, err := json.Marshal(requestbody)
	if err != nil {
		log.Println("Fail to marshal json data:", err)
		return
	}
	resp, err := http.Post(address, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("POST request failed:", err)
		return
	}
	defer resp.Body.Close()

	//读取响应的body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to read response body:", err)
		return
	}
	fmt.Println(respBody)
}
