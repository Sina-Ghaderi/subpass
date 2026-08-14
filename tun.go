package subpass

var zeroConfig Config

func NewTun(config Config) (Tun, error) {

	if config == zeroConfig {
		config = defaltOSparms()
	}

	tun, err := openTunDevice(&config)
	return tun, err
}
