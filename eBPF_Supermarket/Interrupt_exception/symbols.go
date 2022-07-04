package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type KernelSymbolTable struct {
	symbolMap   map[string]KernelSymbol
	initialized bool
}

type KernelSymbol struct {
	Name    string
	Type    string
	Address uint64
	Owner   string
}

func NewKernelSymbolsMap() (*KernelSymbolTable, error) {
	var KernelSymbols = KernelSymbolTable{}
	KernelSymbols.symbolMap = make(map[string]KernelSymbol)
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("Could not open /proc/kallsyms")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		//if the line is less than 3 words, we can't parse it (one or more fields missing)
		if len(line) < 3 {
			continue
		}
		symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			continue
		}
		symbolName := line[2]
		symbolType := line[1]
		symbolOwner := "system"
		//if the line is only 3 words then the symbol is owned by the system
		if len(line) > 3 {
			symbolOwner = line[3]
		}
		symbolKey := fmt.Sprintf("%s_%s", symbolOwner, symbolName)
		KernelSymbols.symbolMap[symbolKey] = KernelSymbol{symbolName, symbolType, symbolAddr, symbolOwner}
	}
	KernelSymbols.initialized = true
	return &KernelSymbols, nil
}

func bin_search(arr []uint64, finddata uint64) uint64 {
    start := 0
    end := len(arr) - 1
    for start < end {	
        mid := (start+end)/2
		if finddata < arr[mid]{
			end = mid
		}else if finddata > arr[mid]{
			start = mid +1 
		}else{
			return arr[mid]
		}
	}
	if start >=1 && arr[start-1] < finddata && finddata <arr[start]{
		return arr[start -1]
	}
    return 0
}

// GetSymbolByAddr returns a symbol by a given address
func (k *KernelSymbolTable) GetSymbolByAddr(addr uint64) (*KernelSymbol, error) {
	var keys []uint64
	for _, Symbol := range k.symbolMap {
		keys = append(keys,Symbol.Address)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	kallsyms_addr :=bin_search(keys,addr)
	
	for _, Symbol := range k.symbolMap {
		if Symbol.Address == kallsyms_addr {
			return &Symbol, nil
		 }
	}
	return nil, fmt.Errorf("symbol not found at address: 0x%x", addr)
}