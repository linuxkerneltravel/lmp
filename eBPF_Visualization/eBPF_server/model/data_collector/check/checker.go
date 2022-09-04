package check

import (
	"regexp"
	"strings"
	"text/template"
)

func VerifyCompleteIndexFormat(line string) bool {
	elements := strings.Fields(line)
	for _, element := range elements {
		matched := VerifySingleIndexFormat(element)
		if !matched {
			return false
		}
	}
	return true
}

func VerifySingleIndexFormat(element string) bool {
	matched, _ := regexp.MatchString(".+\\|.+", element)
	if !matched {
		return false
	}
	return true
}

func EscapeData(line string) string {
	return template.HTMLEscapeString(line)
}

func GetTypeFromData(element string) string {
	var ElementType string
	if matched, _ := regexp.MatchString("^[-+]?[0-9]*\\.[0-9]+$", EscapeData(element)); matched {
		ElementType = "REAL"
	} else {
		if matched, _ := regexp.MatchString("^[-+]?[1-9]\\d*$|^0$", EscapeData(element)); matched {
			ElementType = "INTEGER"
		} else {
			ElementType = "TEXT"
		}
	}
	return ElementType
}

func VerifyMultipleDataMatched(line string, index_parms []string) bool {
	line_parms := strings.Fields(line)
	for i, v := range line_parms {
		if GetTypeFromData(v) != index_parms[i] {
			return false
		}
	}
	return true
}

func OutNumberMatched(line string, indexnumber int) bool {
	line_parms := strings.Fields(line)
	if len(line_parms) != indexnumber {
		return false
	}
	return true
}

func IsPossiblyLost(line string) bool {
	if matched, _ := regexp.MatchString("Possibly lost", line); matched {
		return true
	}
	return false
}
