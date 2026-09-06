//go:build !unix

package instance

import "errors"

func duplicateTunFD(int) (int, error) {
	return -1, errors.New("fd-backed instances are unsupported on this platform")
}
func closeTunFD(int) error { return nil }
