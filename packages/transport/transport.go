package transport

import "github.com/l3montree-dev/oh-my-honeypot/packages/set"

type Transport interface {
	// listen to incoming connections.
	// returns a channel to send data to the client
	Listen() chan<- set.Token
}
