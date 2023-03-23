package transport

type Transport interface {
	// listen to incoming connections.
	// returns a channel to send data to the client
	Listen() chan<- []byte
}
