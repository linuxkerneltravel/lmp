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
