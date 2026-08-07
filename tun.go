package subpass

type Tun interface {
	Name() string
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	ID() uint64
	Destroy() error
}

var zeroConfig Config

func NewTun(config Config) (Tun, error) {

	if config == zeroConfig {
		config = defaltOSparms()
	}

	tun, err := openTunDevice(&config)
	return tun, err
}
