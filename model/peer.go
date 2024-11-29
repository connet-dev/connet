package model

import "github.com/keihaya-com/connet/pbs"

type Peer struct {
	Directs []Route
	Relays  []Route
}

func NewPeerFromPB(peer *pbs.Peer) (Peer, error) {
	directs := make([]Route, len(peer.Directs))
	for i, pb := range peer.Directs {
		if r, err := NewRouteFromPB(pb); err != nil {
			return Peer{}, err
		} else {
			directs[i] = r
		}
	}

	relays := make([]Route, len(peer.Relays))
	for i, pb := range peer.Relays {
		if r, err := NewRouteFromPB(pb); err != nil {
			return Peer{}, err
		} else {
			relays[i] = r
		}
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
