// path_selection.go - mixnet client path selection
// Copyright (C) 2017  David Anthony Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package util provides client utilities
package util

import (
	"errors"
	"fmt"
	mathrand "math/rand"
	"time"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/core/sphinx/constants"
)

// durationFromFloat returns millisecond time.Duration given a float64
func durationFromFloat(delay float64) (time.Duration, error) {
	d, err := time.ParseDuration(fmt.Sprintf("%sms", delay))
	return d, err
}

// getDelays returns a list of delays from
// the Poisson distribution with a given
// lambda argument
func getDelays(lambda float64, count int) []float64 {
	cryptRand := rand.NewMath()
	delays := make([]float64, count)
	for i := 0; i < count; i++ {
		delays[i] = rand.Exp(cryptRand, lambda)
	}
	return delays
}

// sum adds a slice of float64.
// this is used to get the sum of delays
// which are represented as float64s
func sum(input []float64) float64 {
	total := float64(0)
	for _, n := range input {
		total += n
	}
	return total
}

// RouteFactory builds routes and by doing so handles all the
// details of path selection and mix PKI interaction
type RouteFactory struct {
	pki    pki.Client
	nrHops int
	lambda float64
}

// NewRouteFactory creates a new RouteFactory for creating routes
func NewRouteFactory(pki pki.Client, nrHops int, lambda float64) *RouteFactory {
	r := RouteFactory{
		pki:    pki,
		nrHops: nrHops,
		lambda: lambda,
	}
	return &r
}

// getRouteDescriptors returns a slice of mix descriptors,
// one for each hop in the route where each mix descriptor
// was selected from the set of descriptors for that layer
func (r *RouteFactory) getRouteDescriptors() []*pki.MixDescriptor {
	descriptors := make([]*pki.MixDescriptor, r.nrHops)
	for i := 0; i < r.nrHops; i++ {
		layerMixes := r.pki.GetMixesInLayer(i)
		c := mathrand.Intn(len(layerMixes))
		descriptors[i] = layerMixes[c]
	}
	return descriptors
}

// getHopEpochKeys returns a list of keys for each hop, given a list
// of delays and mix descriptors
func (r *RouteFactory) getHopEpochKeys(till time.Duration, delays []float64, descriptors []*pki.MixDescriptor) ([]*ecdh.PublicKey, error) {
	hopDelay := delays[0]
	keys := make([]*ecdh.PublicKey, r.nrHops)
	for i := 0; i < len(descriptors); i++ {
		hopDelay += delays[i]
		hopDuration, err := durationFromFloat(hopDelay)
		if err != nil {
			return nil, err
		}
		if hopDuration < till {
			keys[i] = descriptors[i].EpochAPublicKey
		} else if hopDuration > till && hopDuration < till+epochtime.Period {
			keys[i] = descriptors[i].EpochBPublicKey
		} else if hopDuration > till && hopDuration < till+(2*epochtime.Period) {
			keys[i] = descriptors[i].EpochCPublicKey
		} else {
			return nil, errors.New("error: inappropriate delays")
		}
	}
	return keys, nil
}

// newPathVector returns a slice of PathHops and optionally a new SURB ID
// if the isSURB argument is set to true
func (r *RouteFactory) newPathVector(till time.Duration, delays []float64, descriptors []*pki.MixDescriptor, isSURB bool) ([]*sphinx.PathHop, *[constants.SURBIDLength]byte, error) {
	path := make([]*sphinx.PathHop, r.nrHops)
	var surbID *[constants.SURBIDLength]byte = nil
	keys, err := r.getHopEpochKeys(till, delays, descriptors)
	if err != nil {
		return nil, nil, err
	}
	for i := range path {
		path[i] = new(sphinx.PathHop)
		copy(path[i].ID[:], descriptors[i].ID[:])
		path[i].PublicKey = keys[i]
		if i < r.nrHops-1 {
			// Non-terminal hop, add the delay.
			delay := new(commands.NodeDelay)
			delay.Delay = uint32(delays[i])
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient.
			recipient := new(commands.Recipient)
			_, err := rand.Reader.Read(recipient.ID[:])
			if err != nil {
				return nil, nil, err
			}
			path[i].Commands = append(path[i].Commands, recipient)
			if isSURB {
				surbReply := new(commands.SURBReply)
				id := [constants.SURBIDLength]byte{}
				surbID = &id
				_, err := rand.Reader.Read(surbID[:])
				if err != nil {
					return nil, nil, err
				}
				surbReply.ID = *surbID
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}
	return path, surbID, nil
}

// Next implements section 5.2 Path selection algorithm of the
// Panoramix Mix Network End-to-end Protocol Specification
// see https://github.com/Katzenpost/docs/blob/master/specs/end_to_end.txt
func (r *RouteFactory) Next() ([]*sphinx.PathHop, []*sphinx.PathHop, *[constants.SURBIDLength]byte, error) {
	// 1. Sample all forward and SURB delays.
	forwardDelays := getDelays(r.lambda, r.nrHops)
	replyDelays := getDelays(r.lambda, r.nrHops)
	// 2. Ensure total delays doesn't exceed (time_till next_epoch) +
	//    2 * epoch_duration, as keys are only published 3 epochs in
	//    advance.
	_, _, till := epochtime.Now()
	forwardDuration, err := durationFromFloat(sum(forwardDelays))
	if err != nil {
		return nil, nil, nil, err
	}
	replyDuration, err := durationFromFloat(sum(replyDelays))
	if err != nil {
		return nil, nil, nil, err
	}
	if forwardDuration+replyDuration > till+(2*epochtime.Period) {
		return nil, nil, nil, errors.New("selected delays exceed permitted epochtime range")
	}
	// 3. Pick forward and SURB mixes (Section 5.2.1).
	forwardDescriptors := r.getRouteDescriptors()
	replyDescriptors := r.getRouteDescriptors()
	// 4. Ensure that the forward and SURB mixes have a published key that
	//    will allow them to decrypt the packet at the time of it's expected
	//    arrival.
	forwardPath, _, err := r.newPathVector(till, forwardDelays, forwardDescriptors, false)
	if err != nil {
		return nil, nil, nil, err
	}
	replyPath, surbID, err := r.newPathVector(till, replyDelays, replyDescriptors, true)
	if err != nil {
		return nil, nil, nil, err
	}
	return forwardPath, replyPath, surbID, nil
}
