package honeypot

import "gitlab.com/neuland-homeland/honeypot/packages/set"

type Honeypot interface {
	// Start starts the honeypot
	// should not block
	Start() error
	// GetSETChannel returns the channel the honeypot is posting SET events to.
	GetSETChannel() <-chan set.Token
}
