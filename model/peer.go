package model

import "github.com/keihaya-com/connet/pbs"

type Peer struct {
	Directs []Route
	Relays  []Route
}

func NewPeerFromPB(peer *pbs.Peer) (Peer, error) {
	directs, err := RoutesFromPB(peer.Directs)
	if err != nil {
		return Peer{}, err
	}

	relays, err := RoutesFromPB(peer.Relays)
	if err != nil {
		return Peer{}, err
	}

	return Peer{Directs: directs, Relays: relays}, nil
}

func (p Peer) PB() *pbs.Peer {
	peer := &pbs.Peer{}
	for _, dst := range p.Directs {
		peer.Directs = append(peer.Directs, dst.PB())
	}
	for _, dst := range p.Relays {
		peer.Relays = append(peer.Relays, dst.PB())
	}
	return peer
}

func PeersToPB(peers []Peer) []*pbs.Peer {
	result := make([]*pbs.Peer, len(peers))
	for i, p := range peers {
		result[i] = p.PB()
	}
	return result
}

func PeersFromPB(peers []*pbs.Peer) ([]Peer, error) {
	var err error
	result := make([]Peer, len(peers))
	for i, p := range peers {
		result[i], err = NewPeerFromPB(p)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
