package cpumask

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var NR_CPU_IDS = 256

type Cpumask struct {
	mask []uint64
}

// NewCpumask creates a new empty cpumask
func NewCpumask() *Cpumask {
	size := (NR_CPU_IDS + 63) / 64
	return &Cpumask{
		mask: make([]uint64, size),
	}
}

func FromStr(s string) (*Cpumask, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "none":
		c := NewCpumask()
		return c, nil
	case "all":
		c := NewCpumask()
		for i := range c.mask {
			c.mask[i] = ^uint64(0)
		}
		c.clearExcessBits()
		return c, nil
	}

	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}

	if len(s)%2 != 0 {
		s = "0" + s
	}

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cpumask %q: %v", s, err)
	}

	c := NewCpumask()
	for i := 0; i < len(data)/2; i++ {
		data[i], data[len(data)-1-i] = data[len(data)-1-i], data[i]
	}

	for index, val := range data {
		for bit := 0; bit < 8; bit++ {
			if (val & (1 << bit)) != 0 {
				cpu := index*8 + bit
				if cpu >= NR_CPU_IDS {
					return nil, fmt.Errorf("cpu %d in cpumask %q is larger than max %d", cpu, s, NR_CPU_IDS)
				}
				if err := c.SetCPU(cpu); err != nil {
					return nil, err
				}
			}
		}
	}

	return c, nil
}

func (c *Cpumask) clearExcessBits() {
	remainder := NR_CPU_IDS % 64
	if remainder != 0 {
		mask := ^uint64(0) >> (64 - remainder)
		c.mask[len(c.mask)-1] &= mask
	}
}

func (c *Cpumask) checkCPU(cpu int) error {
	if cpu < 0 || cpu >= NR_CPU_IDS {
		return fmt.Errorf("Invalid CPU %d, max %d", cpu, NR_CPU_IDS)
	}
	return nil
}

func (c *Cpumask) SetAll() {
	for i := range c.mask {
		c.mask[i] = ^uint64(0)
	}
	c.clearExcessBits()
}

func (c *Cpumask) ClearAll() {
	for i := range c.mask {
		c.mask[i] = 0
	}
}

func (c *Cpumask) SetCPU(cpu int) error {
	if err := c.checkCPU(cpu); err != nil {
		return err
	}
	idx := cpu / 64
	bit := uint(cpu % 64)
	c.mask[idx] |= (1 << bit)
	return nil
}

func (c *Cpumask) ClearCPU(cpu int) error {
	if err := c.checkCPU(cpu); err != nil {
		return err
	}
	idx := cpu / 64
	bit := uint(cpu % 64)
	c.mask[idx] &^= (1 << bit)
	return nil
}

func (c *Cpumask) TestCPU(cpu int) bool {
	if cpu < 0 || cpu >= NR_CPU_IDS {
		return false
	}
	idx := cpu / 64
	bit := uint(cpu % 64)
	return (c.mask[idx] & (1 << bit)) != 0
}

func (c *Cpumask) Weight() int {
	count := 0
	for _, block := range c.mask {
		count += popcount(block)
	}
	return count
}

func popcount(x uint64) int {
	count := 0
	for x != 0 {
		x &= x - 1
		count++
	}
	return count
}

func (c *Cpumask) IsEmpty() bool {
	return c.Weight() == 0
}

func (c *Cpumask) IsFull() bool {
	return c.Weight() == NR_CPU_IDS
}

func (c *Cpumask) Len() int {
	return NR_CPU_IDS
}

func (c *Cpumask) Not() *Cpumask {
	newMask := &Cpumask{mask: make([]uint64, len(c.mask))}
	for i, v := range c.mask {
		newMask.mask[i] = ^v
	}
	newMask.clearExcessBits()
	return newMask
}

func (c *Cpumask) And(other *Cpumask) *Cpumask {
	if len(c.mask) != len(other.mask) {
		return nil
	}
	newMask := &Cpumask{mask: make([]uint64, len(c.mask))}
	for i := range c.mask {
		newMask.mask[i] = c.mask[i] & other.mask[i]
	}
	return newMask
}

func (c *Cpumask) Or(other *Cpumask) *Cpumask {
	newMask := &Cpumask{mask: make([]uint64, len(c.mask))}
	for i := range c.mask {
		newMask.mask[i] = c.mask[i] | other.mask[i]
	}
	return newMask
}

func (c *Cpumask) Xor(other *Cpumask) *Cpumask {
	newMask := &Cpumask{mask: make([]uint64, len(c.mask))}
	for i := range c.mask {
		newMask.mask[i] = c.mask[i] ^ other.mask[i]
	}
	newMask.clearExcessBits()
	return newMask
}

func (c *Cpumask) Iter() []int {
	var cpus []int
	for cpu := 0; cpu < NR_CPU_IDS; cpu++ {
		if c.TestCPU(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	return cpus
}

func (c *Cpumask) String() string {
	var sb strings.Builder
	for cpu := NR_CPU_IDS - 1; cpu >= 0; cpu-- {
		if c.TestCPU(cpu) {
			sb.WriteRune('1')
		} else {
			sb.WriteRune('0')
		}
	}
	return sb.String()
}
