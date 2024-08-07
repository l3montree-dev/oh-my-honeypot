package honeypot

import (
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/oh-my-honeypot/packages/types"
	"github.com/l3montree-dev/oh-my-honeypot/packages/utils"
)

const (
	PortEventID       = "https://github.com/l3montree-dev/oh-my-honeypot/json-schema/port-scanning.json"
	LoginEventID      = "https://github.com/l3montree-dev/oh-my-honeypot/json-schema/ssh-login-attempt.json"
	HTTPEventID       = "https://github.com/l3montree-dev/oh-my-honeypot/json-schema/http-request.json"
	CredentialEventID = "https://github.com/l3montree-dev/oh-my-honeypot/json-schema/credential-theft.json"
)

type Honeypot interface {
	// Start starts the honeypot
	// should not block
	Start() error
	// GetSETChannel returns the channel the honeypot is posting SET events to.
	GetSETChannel() <-chan types.Set
}

func DetectPortScan(tokens []types.Set) []types.Set {
	// if there are more than 5 tokens in the slice from the same IP
	// it is possible that a port scan is happening
	subCount := make(map[string][]int)
	for _, token := range tokens {
		if _, ok := subCount[token.SUB]; !ok {
			subCount[token.SUB] = make([]int, 0)
		}
		portStr := token.Events["https://github.com/l3montree-dev/oh-my-honeypot/json-schema/port"]["port"].(string)
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
				func(t types.Set) bool {
					return t.SUB != sub
				},
			)
			sort.Slice(ports, func(i, j int) bool {
				return ports[i] < ports[j]
			})
			tokens = append(tokens, types.Set{
				SUB: sub,
				ISS: "github.com/l3montree-dev/oh-my-honeypot/packages/honeypot",
				IAT: time.Now().Unix(),
				JTI: uuid.New().String(),
				Events: map[string]map[string]interface{}{
					"https://github.com/l3montree-dev/oh-my-honeypot/json-schema/port-scan": {
						"ports": ports,
					},
				},
			})
		}
	}
	return tokens
}
