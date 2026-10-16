package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestQueryProcessExeMovedWhileRunning verifies that on Windows, if a running
// binary is moved/renamed to another folder on the same volume, QueryFullProcessImageName
// successfully resolves the new live path on disk rather than the stale launch path.
func TestQueryProcessExeMovedWhileRunning(t *testing.T) {
	ping := filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE")
	b, err := os.ReadFile(ping)
	if err != nil {
		t.Skip("no PING.EXE:", err)
	}

	dir1 := t.TempDir()
	dir2 := t.TempDir()

	exe1 := filepath.Join(dir1, "test-magpie.exe")
	exe2 := filepath.Join(dir2, "test-magpie-moved.exe")

	if err := os.WriteFile(exe1, b, 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exe1, "-n", "30", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Move the running executable to dir2 (valid on same NTFS volume)
	if err := os.Rename(exe1, exe2); err != nil {
		t.Skipf("cannot rename running executable across locations: %v", err)
	}

	if _, err := os.Stat(exe1); err == nil {
		t.Fatal("exe1 still exists after rename")
	}
	if _, err := os.Stat(exe2); err != nil {
		t.Fatalf("exe2 does not exist after rename: %v", err)
	}

	// Query live executable path from process handle
	hProcess, err := syscall.OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatalf("OpenProcess failed: %v", err)
	}
	defer syscall.CloseHandle(hProcess)

	resolved, err := queryProcessExe(hProcess)
	if err != nil {
		t.Fatalf("queryProcessExe failed: %v", err)
	}

	resolvedNorm := filepath.Clean(strings.ToLower(resolved))
	expectedNorm := filepath.Clean(strings.ToLower(exe2))
	if resolvedNorm != expectedNorm {
		t.Fatalf("resolved path mismatch:\n got:  %q\n want: %q", resolved, exe2)
	}
}

// TestCurrentExeSelf verifies that currentExe() returns the running executable
// and that Executable() succeeds.
func TestCurrentExeSelf(t *testing.T) {
	exe, err := currentExe()
	if err != nil {
		t.Fatalf("currentExe() failed: %v", err)
	}
	if _, err := os.Stat(exe); err != nil {
		t.Fatalf("currentExe() returned non-existent path %q: %v", exe, err)
	}
	resolved, err := Executable()
	if err != nil {
		t.Fatalf("Executable() failed: %v", err)
	}
	if resolved == "" {
		t.Fatal("Executable() returned empty string")
	}
}
