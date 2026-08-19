package command

import (
	"os"
	"testing"
)

type capture struct {
	stdout string
	stderr string
}

// captureOutput records what fn writes to the process streams, with errOut left
// nil so fail() takes the fallback every real run takes. Discarding the streams
// instead (see silenceOutput) hides a command that fails without saying why, and
// a message landing on the stdout that the shell evals.
//
// Not safe for parallel tests: it swaps process-wide state.
func captureOutput(t *testing.T, fn func()) capture {
	t.Helper()
	outFile := tempStream(t, "stdout")
	errFile := tempStream(t, "stderr")

	savedOut, savedErr, savedErrOut := os.Stdout, os.Stderr, errOut
	restore := func() { os.Stdout, os.Stderr, errOut = savedOut, savedErr, savedErrOut }
	// Deferred as well as called below: fn may abort the test through t.Fatal,
	// and leaving os.Stdout on a temp file that cleanup deletes would silence
	// every later test in the package.
	defer restore()
	os.Stdout, os.Stderr, errOut = outFile, errFile, nil

	fn()

	restore()
	return capture{stdout: readStream(t, outFile), stderr: readStream(t, errFile)}
}

func tempStream(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func readStream(t *testing.T, f *os.File) string {
	t.Helper()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
