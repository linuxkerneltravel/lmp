package checker

func interfacetoorigin(value interface{}) interface{} {
	switch value.(type) {
	case string:
		op, _ := value.(string)
		return op
	case int32:
		op, _ := value.(int32)
		return op
	}
	return nil
}
