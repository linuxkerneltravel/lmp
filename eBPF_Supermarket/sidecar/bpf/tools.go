package bpf

import (
	"fmt"
	"strconv"
	"strings"
)

type IntFilterGenerator struct {
	Name    string
	List    []int
	Reverse bool // skip event if `Reverse` is true
}

// Generate generate filter statement for BPF program in C code
func (fg IntFilterGenerator) Generate() string {
	if len(fg.List) == 0 {
		return ""
	}

	filter := ""
	if fg.Reverse == false {
		filter = fmt.Sprintf(" %s != %s", fg.Name, strconv.Itoa(fg.List[0]))
		for _, port := range fg.List[1:] {
			filter += fmt.Sprintf(" && %s != %s", fg.Name, strconv.Itoa(port))
		}
	} else {
		filter = fmt.Sprintf(" %s == %s", fg.Name, strconv.Itoa(fg.List[0]))
		for _, port := range fg.List[1:] {
			filter += fmt.Sprintf(" || %s == %s", fg.Name, strconv.Itoa(port))
		}
	}

	filter = fmt.Sprintf("if (%s) { return 0; }", filter)
	return filter
}

type FamilyFilterGenerator struct {
	List []string
}

func (fg FamilyFilterGenerator) Generate() string {
	if len(fg.List) == 0 {
		return ""
	}

	filter := GetFamilyFilter(fg.List[0])
	for _, family := range fg.List[1:] {
		filter += GetFamilyFilter(family) // not so formatted here...
	}
	filter = fmt.Sprintf("if (%s) { return 0; }", filter)
	return filter
}

func GetIpv4Filter() string {
	return "if (family != AF_INET) { return 0; }"
}

func GetIpv6Filter() string {
	return "if (family != AF_INET6) { return 0; }"
}

func GetIpv4AndIpv6ReverseFilter() string {
	return "if (family == AF_INET || family == AF_INET6) { return 0; }"
}

func GetFamilyFilter(family string) string {
	family = strings.ToLower(family)

	familyMap := map[string]string{
		"ipv4":  GetIpv4Filter(),
		"ipv6":  GetIpv6Filter(),
		"notip": GetIpv4AndIpv6ReverseFilter(),
	}

	res, ok := familyMap[family]

	if ok != true {
		panic("Family " + family + " not supported")
	}

	return res

}
