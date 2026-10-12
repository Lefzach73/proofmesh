//go:build !darwin && !linux

package state

import (
	"context"
	"fmt"
)

func lock(context.Context, string) (func(), error) {
	return nil, fmt.Errorf("durable writer locking supports macOS/Linux only")
}
