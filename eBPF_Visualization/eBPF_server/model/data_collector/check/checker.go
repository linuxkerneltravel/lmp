package check

import (
	"errors"
	"regexp"
)

func VerifyIndexFormat(line string) error {
	matched, err := regexp.MatchString("[a-zA-Z0-9_-]+\\|[a-zA-Z0-9_-]+", line)
	if err != nil {
		return err
	}
	if !matched {
		err = errors.New("Format Mismatch!")
		return err
	}
	return nil
}
