package axiam

// MinGoVersion is the minimum Go language version this module supports, as
// major.minor.
//
// It mirrors the `go` directive in go.mod. Go's toolchain enforces that
// directive at build time, but a consumer has no way to read it back at run
// time — `debug.ReadBuildInfo` reports the toolchain that produced the binary
// and the module graph, never a dependency's declared language version. This
// constant is the readable half, so a deployment preflight or a startup
// assertion can compare the two without hardcoding a number that goes stale.
//
// The value is verified against go.mod by version_policy_test.go, so the two
// cannot drift.
//
// The module is built and tested against this version and against the current
// Go release; Go supports exactly the two most recent majors, so that pair is
// the whole supported range. See examples/version-compatibility.
const MinGoVersion = "1.26"
