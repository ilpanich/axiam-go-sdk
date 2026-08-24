// Command version-compatibility reports the running Go toolchain against the
// range of Go versions this SDK supports.
//
// The SDK is built against its floor (axiam.MinGoVersion, mirroring the `go`
// directive in go.mod) and additionally tested against the current Go release.
// Go supports exactly the two most recent majors, so that pair is the entire
// supported range rather than a sample of it.
//
// The Go toolchain already refuses to build a module whose `go` directive it
// cannot satisfy, so the below-floor case cannot normally reach production —
// but a binary cross-built elsewhere, or a vendored tree, can. What this
// example is actually useful for is the other end: reporting that the
// toolchain in use is newer than anything the SDK has a green build against,
// which nothing else surfaces.
//
// This example is illustrative/compilable — it reads nothing from the network
// and does not require a live AXIAM server to
// `go build ./examples/version-compatibility/...`.
//
// Run: go run ./examples/version-compatibility
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

func main() {
	// runtime.Version() is "go1.26.7" on a released toolchain, or "devel ..."
	// on a tip build.
	running := strings.TrimPrefix(runtime.Version(), "go")

	fmt.Printf("running toolchain: %s\n", runtime.Version())
	fmt.Printf("SDK minimum Go:    %s\n", axiam.MinGoVersion)

	// debug.ReadBuildInfo additionally names the SDK version actually linked
	// in, which is the other half of a useful preflight line. It is absent
	// when the binary was built with -buildinfo=false or run via `go run` in
	// some configurations, so it is reported opportunistically.
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/ilpanich/axiam-go-sdk" {
				fmt.Printf("linked SDK:        %s\n", dep.Version)
				break
			}
		}
	}

	runMajor, runMinor, ok := majorMinor(running)
	if !ok {
		fmt.Printf("UNKNOWN: %q is not a released Go version; skipping the check.\n",
			runtime.Version())
		return
	}
	minMajor, minMinor, ok := majorMinor(axiam.MinGoVersion)
	if !ok {
		fmt.Fprintf(os.Stderr, "malformed MinGoVersion %q\n", axiam.MinGoVersion)
		os.Exit(2)
	}

	switch {
	case runMajor < minMajor || (runMajor == minMajor && runMinor < minMinor):
		fmt.Printf("UNSUPPORTED: Go %d.%d is below the %s floor. The toolchain "+
			"normally refuses this outright; seeing it here means the binary "+
			"was produced somewhere else.\n", runMajor, runMinor, axiam.MinGoVersion)
		os.Exit(1)
	case runMajor == minMajor && runMinor > minMinor+1:
		// Beyond floor+1 means the floor has fallen outside Go's two-release
		// support window, so the SDK's declared minimum is itself unsupported.
		fmt.Printf("UNTESTED: Go %d.%d is more than one release past the %s "+
			"floor, which is outside Go's two-release support window. Expected "+
			"to work, but no green build proves it.\n",
			runMajor, runMinor, axiam.MinGoVersion)
	default:
		fmt.Printf("SUPPORTED: Go %d.%d is inside the tested range (%s and the "+
			"release after it).\n", runMajor, runMinor, axiam.MinGoVersion)
	}
}

// majorMinor parses the leading "X.Y" of a Go version string.
func majorMinor(v string) (major, minor int, ok bool) {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
