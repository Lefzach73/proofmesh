//go:build !darwin && !linux

package main

import "errors"

func leaseTrustFile(string) (func(), error) {
	return nil, errors.New("durable live trust requires the tested macOS/Linux file lock implementation")
}
