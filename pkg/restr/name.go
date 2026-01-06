package restr

import "regexp"

type Name struct {
	Expression *regexp.Regexp `json:"expression,omitempty"`
}

func ParseName(s string) (Name, error) {
	exp, err := regexp.Compile(s)
	if err != nil {
		return Name{}, err
	}
	return Name{exp}, nil
}

func (r Name) IsAllowed(s string) bool {
	if r.Expression == nil {
		return true
	}
	return r.Expression.MatchString(s)
}
