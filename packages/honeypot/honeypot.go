package honeypot

import "gitlab.com/neuland-homeland/honeypot/packages/set"

type Honeypot interface {
	// Start starts the honeypot
	// should not block
	Start() error
	// Stop stops the honeypot
	Stop() error
	// GetPort returns the port the honeypot is listening on
	GetPort() int
	// GetSETChannel returns the channel the honeypot is posting SET events to.
	GetSETChannel() <-chan set.Token
}
