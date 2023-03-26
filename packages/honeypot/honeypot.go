package honeypot

import (
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
	"gitlab.com/neuland-homeland/honeypot/packages/utils"
)

type Honeypot interface {
	// Start starts the honeypot
	// should not block
	Start() error
	// GetSETChannel returns the channel the honeypot is posting SET events to.
	GetSETChannel() <-chan set.Token
}

func DetectPortScan(tokens []set.Token) []set.Token {
	// if there are more than 5 tokens in the slice from the same IP
	// it is possible that a port scan is happening
	subCount := make(map[string][]int)
	for _, token := range tokens {
		if _, ok := subCount[token.SUB]; !ok {
			subCount[token.SUB] = make([]int, 0)
		}
		portStr := token.Events["https://gitlab.com/neuland-homeland/honeypot/json-schema/port"]["port"].(string)
		port, _ := strconv.Atoi(portStr)
		subCount[token.SUB] = append(subCount[token.SUB], port)
	}

	for sub, ports := range subCount {
		if len(ports) > 5 {
			// port scan detected
			// create a new token
			// remove the tokens from the slice
			tokens = utils.Filter(
				tokens,
				func(t set.Token) bool {
					return t.SUB != sub
				},
			)
			sort.Slice(ports, func(i, j int) bool {
				return ports[i] < ports[j]
			})
			tokens = append(tokens, set.Token{
				SUB: sub,
				ISS: "gitlab.com/neuland-homeland/honeypot/packages/honeypot",
				IAT: time.Now().Unix(),
				JTI: uuid.New().String(),
				TOE: time.Now().Unix(),
				Events: map[string]map[string]interface{}{
					"https://gitlab.com/neuland-homeland/honeypot/json-schema/port-scan": {
						"ports": ports,
					},
				},
			})
		}
	}
	return tokens
}
