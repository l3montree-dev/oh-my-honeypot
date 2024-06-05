package transport

import "github.com/l3montree-dev/oh-my-honeypot/packages/types"

type Transport interface {
	// listen to incoming connections.
	// returns a channel to send data to the client
	Listen() chan<- types.Set
}
