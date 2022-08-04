package check

import (
	"errors"
	"regexp"
	"text/template"
)

func VerifyIndexFormat(line string) error {
	matched, err := regexp.MatchString(".+\\|.+", line)
	if err != nil {
		return err
	}
	if !matched {
		err = errors.New("Format Mismatch!")
		return err
	}
	return nil
}

func EscapeData(line string) string {
	return template.HTMLEscapeString(line)
}
