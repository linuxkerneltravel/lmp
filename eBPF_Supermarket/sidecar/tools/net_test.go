package tools

import (
	"testing"
)

func TestEndianness(t *testing.T) {
	cases := []struct {
		num          int
		hostNumShort int
		hostNumLong  int
	}{
		{15006, 40506, 2654601216},
		{9080, 30755, 2015559680},
	}
	for i := 0; i < len(cases); i++ {
		a := NetToHostShort(uint16(cases[i].num))
		if int(a) != cases[i].hostNumShort {
			t.Errorf("NetToHostShort %d failed, expected: '%d', got '%d'", cases[i].num, cases[i].hostNumShort, a)
		}

		b := NetToHostLong(uint32(cases[i].num))
		if int(b) != cases[i].hostNumLong {
			t.Errorf("NetToHostLong %d failed, expected: '%d', got '%d'", cases[i].num, cases[i].hostNumLong, b)
		}

		c := HostToNetShort(uint16(cases[i].hostNumShort))
		if int(c) != cases[i].num {
			t.Errorf("HostToNetShort %d failed, expected: '%d', got '%d'", cases[i].hostNumShort, cases[i].num, c)
		}

		d := HostToNetLong(uint32(cases[i].hostNumLong))
		if int(d) != cases[i].num {
			t.Errorf("HostToNetLong %d failed, expected: '%d', got '%d'", cases[i].hostNumLong, cases[i].num, d)
		}
	}
}
