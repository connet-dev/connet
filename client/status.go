package client

type PeerStatus struct {
	Relays      []RelayConnection `json:"relays"`
	Connections []PeerConnection  `json:"connections"`
}

type RelayConnection struct {
	ID       string `json:"id"`
	Hostport string `json:"hostport"`
}

type PeerConnection struct {
	ID    string `json:"id"`
	Style string `json:"style"`
	Addr  string `json:"addr"`
}

func (p *peer) status() (PeerStatus, error) {
	stat := PeerStatus{}

	relays, err := p.relayConns.Peek()
	if err != nil {
		return PeerStatus{}, err
	}
	for id, conn := range relays {
		stat.Relays = append(stat.Relays, RelayConnection{
			ID:       string(id),
			Hostport: conn.hp.String(),
		})
	}

	conns, err := p.peerConns.Peek()
	if err != nil {
		return PeerStatus{}, err
	}
	for key, conn := range conns {
		stat.Connections = append(stat.Connections, PeerConnection{
			ID:    key.id,
			Style: key.style.String(),
			Addr:  conn.RemoteAddr().String(),
		})
	}

	return stat, nil
}
