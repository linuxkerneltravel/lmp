package BPF

import (
	"lmp_ui/deployments/message"
	"os"
)

type BPFBody struct{}

func (b *BPFBody)Generator(m *message.ConfigMessage) os.File {
	return os.File{}
}




