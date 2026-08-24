package axiam

// Language-version support policy.
//
// "Which Go does this module support?" is declared in two places that nothing
// compares:
//
//  1. the `go` directive in go.mod — what the toolchain enforces on every
//     consumer, and what `go get` reports when it refuses;
//  2. the `go` matrix in .github/workflows/sdk-ci-go.yml — the only one that
//     is ever compiled.
//
// Before this test existed CI built one toolchain, 1.26.7, and go.mod declared
// 1.26. That agreed, but nothing held it that way and nothing built the newest
// release at all: a 1.27-only stdlib addition would have compiled clean here
// and broken every consumer who took the module at its declared word.
//
// Go supports exactly the two most recent majors, so floor + newest is not a
// sampling of the supported range — it is the whole of it.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// `go 1.26` in go.mod. The directive carries major.minor only (a patch there
// would pin a toolchain, which this module deliberately does not do).
var goDirectiveRe = regexp.MustCompile(`(?m)^go (\d+)\.(\d+)$`)

// `go: ['1.26.7', '1.27.0']` in the CI test matrix.
var ciMatrixRe = regexp.MustCompile(`(?m)^\s*go:\s*\[([^\]]*)\]\s*$`)

type version struct{ major, minor, patch int }

func (v version) String() string {
	return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
}

// majorMinor compares only the language version, which is what go.mod declares.
func (v version) majorMinor() (int, int) { return v.major, v.minor }

func parseVersion(t *testing.T, s string) version {
	t.Helper()
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		t.Fatalf("cannot parse %q as a Go version", s)
	}
	out := version{}
	for i, dst := range []*int{&out.major, &out.minor, &out.patch} {
		if i >= len(parts) {
			break
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			t.Fatalf("cannot parse %q as a Go version: %v", s, err)
		}
		*dst = n
	}
	return out
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	// Tests run with the package directory as the working directory, which is
	// the module root for this package.
	b, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(b)
}

// goModFloor returns the language version declared by go.mod.
func goModFloor(t *testing.T) version {
	t.Helper()
	m := goDirectiveRe.FindStringSubmatch(readRepoFile(t, "go.mod"))
	if m == nil {
		t.Fatal("go.mod has no `go X.Y` directive this test can read. The " +
			"support policy is a single language version; if that has " +
			"deliberately changed, update this test rather than the regexp.")
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return version{major: major, minor: minor}
}

// ciMatrix returns the toolchains the gating CI job builds, ascending.
func ciMatrix(t *testing.T) []version {
	t.Helper()
	matches := ciMatrixRe.FindAllStringSubmatch(
		readRepoFile(t, filepath.Join(".github", "workflows", "sdk-ci-go.yml")), -1)
	if len(matches) != 1 {
		t.Fatalf("expected exactly one `go:` matrix in sdk-ci-go.yml, found %d; "+
			"a second would mean this test only checks one of them", len(matches))
	}
	var out []version
	for _, entry := range strings.Split(matches[0][1], ",") {
		entry = strings.Trim(strings.TrimSpace(entry), `'"`)
		if entry == "" {
			continue
		}
		out = append(out, parseVersion(t, entry))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].major != out[j].major {
			return out[i].major < out[j].major
		}
		if out[i].minor != out[j].minor {
			return out[i].minor < out[j].minor
		}
		return out[i].patch < out[j].patch
	})
	return out
}

// TestMinGoVersionMatchesGoMod keeps the exported constant honest. It is the
// only part of the floor a consumer can read at run time, so a stale value is
// worse than no value: a preflight built on it would pass while the toolchain
// refused the build.
func TestMinGoVersionMatchesGoMod(t *testing.T) {
	floor := goModFloor(t)
	want := strconv.Itoa(floor.major) + "." + strconv.Itoa(floor.minor)
	if MinGoVersion != want {
		t.Errorf("MinGoVersion is %q but go.mod declares go %s", MinGoVersion, want)
	}
}

// TestCIBuildsTheDeclaredFloor is the assertion that keeps the go.mod directive
// honest. Without a floor leg, a 1.27-only stdlib call compiles clean and the
// breakage lands on a consumer.
func TestCIBuildsTheDeclaredFloor(t *testing.T) {
	floor := goModFloor(t)
	fMajor, fMinor := floor.majorMinor()
	for _, v := range ciMatrix(t) {
		if m, n := v.majorMinor(); m == fMajor && n == fMinor {
			return
		}
	}
	t.Errorf("go.mod declares go %d.%d but no CI leg builds it: %v",
		fMajor, fMinor, ciMatrix(t))
}

// TestCINeverBuildsBelowTheFloor catches the matrix being edited downward
// without go.mod following. Such a leg cannot even compile the module.
func TestCINeverBuildsBelowTheFloor(t *testing.T) {
	floor := goModFloor(t)
	fMajor, fMinor := floor.majorMinor()
	for _, v := range ciMatrix(t) {
		m, n := v.majorMinor()
		if m < fMajor || (m == fMajor && n < fMinor) {
			t.Errorf("CI builds Go %s, below the go.mod floor %d.%d",
				v, fMajor, fMinor)
		}
	}
}

// TestCIMatrixIsFloorAndNewest pins the policy itself: exactly two legs, the
// ends of the range. Go supports the two most recent majors, so this is the
// whole supported range rather than a sample of it.
func TestCIMatrixIsFloorAndNewest(t *testing.T) {
	matrix := ciMatrix(t)
	if len(matrix) != 2 {
		t.Fatalf("expected exactly 2 CI legs (floor + newest), got %d: %v",
			len(matrix), matrix)
	}
	floor := goModFloor(t)
	fMajor, fMinor := floor.majorMinor()
	if m, n := matrix[0].majorMinor(); m != fMajor || n != fMinor {
		t.Errorf("lowest CI leg is %s, but go.mod declares %d.%d",
			matrix[0], fMajor, fMinor)
	}
	// Go's support window is exactly two majors wide, so the newest leg is the
	// release immediately after the floor. Anything wider means the floor has
	// fallen out of support.
	newest := matrix[1]
	if newest.major != fMajor || newest.minor != fMinor+1 {
		t.Errorf("newest CI leg is %s; with a %d.%d floor and Go's two-release "+
			"support window it should be %d.%d.x — if Go has moved on, raise "+
			"the go.mod directive too",
			newest, fMajor, fMinor, fMajor, fMinor+1)
	}
}

// TestRunningToolchainSatisfiesTheFloor closes the loop: whichever leg CI
// actually launched, the module's declared minimum covers it.
func TestRunningToolchainSatisfiesTheFloor(t *testing.T) {
	// runtime.Version() is "go1.26.7", or "devel ..." on a tip build.
	raw := strings.TrimPrefix(runtime.Version(), "go")
	if !regexp.MustCompile(`^\d+\.\d+`).MatchString(raw) {
		t.Skipf("running toolchain %q is not a released version", runtime.Version())
	}
	running := parseVersion(t, raw)
	floor := goModFloor(t)
	fMajor, fMinor := floor.majorMinor()
	m, n := running.majorMinor()
	if m < fMajor || (m == fMajor && n < fMinor) {
		t.Errorf("tests are running on Go %d.%d, below the go.mod floor %d.%d",
			m, n, fMajor, fMinor)
	}
}
