package statusc

import "fmt"

type Status struct{ string }

var (
	NotConnected = Status{"not_connected"}
	Connected    = Status{"connected"}
	Reconnecting = Status{"reconnecting"}
	Disconnected = Status{"disconnected"}
)

func (s Status) String() string {
	return s.string
}

func (s Status) MarshalText() ([]byte, error) {
	return []byte(s.string), nil
}

func (s *Status) UnmarshalText(b []byte) error {
	switch str := string(b); str {
	case NotConnected.string:
		*s = NotConnected
	case Connected.string:
		*s = Connected
	case Reconnecting.string:
		*s = Reconnecting
	case Disconnected.string:
		*s = Disconnected
	default:
		return fmt.Errorf("invalid status '%s'", s)
	}
	return nil
}
