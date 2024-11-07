package certc

import "crypto/tls"

func Load(cert, key string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(cert, key)
}
