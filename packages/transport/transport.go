package transport

import "gitlab.com/neuland-homeland/honeypot/packages/set"

type Transport interface {
	// listen to incoming connections.
	// returns a channel to send data to the client
	Listen() chan<- set.Token
}
