package sample

type Registry struct{}

func ParseName(value string) string { return value }
func (Registry) Find(name string) string { return ParseName(name) }
