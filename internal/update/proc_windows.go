package update

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/yetone/magpie/internal/proc"
)

const (
	synchronize  = 0x00100000
	waitTimeout  = 0x00000102
	detachedProc = 0x00000008
	newProcGroup = 0x00000200
	suspended    = 0x00000004
	noWindow     = 0x08000000
)

var (
	procQueryFullProcessImageName = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")
	procGetCurrentProcess         = syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentProcess")
)

// currentExe returns the path to the running executable.
// On Windows, if a running binary was moved or renamed to another folder on the
// same NTFS volume, os.Executable() (which calls GetModuleFileName) continues to
// return the stale launch path recorded in the PEB. When that file no longer
// exists on disk, QueryFullProcessImageName queries the kernel for the live image path.
func currentExe() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		if _, statErr := os.Stat(exe); statErr == nil {
			return exe, nil
		}
	}
	if live, liveErr := queryLiveExe(); liveErr == nil {
		if _, statErr := os.Stat(live); statErr == nil {
			return live, nil
		}
	}
	return exe, err
}

func queryLiveExe() (string, error) {
	h, _, _ := procGetCurrentProcess.Call()
	if h == 0 {
		return "", syscall.GetLastError()
	}
	return queryProcessExe(syscall.Handle(h))
}

func queryProcessExe(h syscall.Handle) (string, error) {
	b := make([]uint16, syscall.MAX_PATH)
	for {
		size := uint32(len(b))
		r1, _, err := procQueryFullProcessImageName.Call(
			uintptr(h),
			0,
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if r1 == 0 {
			if errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) && len(b) < 32768 {
				b = make([]uint16, len(b)*2)
				continue
			}
			return "", err
		}
		return syscall.UTF16ToString(b[:size]), nil
	}
}

// alive reports whether pid is still running.
func alive(pid int) bool {
	h, err := syscall.OpenProcess(synchronize, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	ev, _ := syscall.WaitForSingleObject(h, 0)
	return ev == waitTimeout
}

// detach starts a relaunched magpie outside this one's console, so it
// outlives it. It gets no console at all, so Windows ignores the
// CREATE_NO_WINDOW proc may have set.
func detach(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= detachedProc | newProcGroup
}

// Reexec starts exe with args and env in this console and returns, for
// the caller to exit: Windows can't run another program in a process's
// place, so the new version goes on printing where this one did.
func Reexec(exe string, args, env []string) error {
	cmd := proc.Command(exe, args...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// trialStart starts path suspended and ends it at once: Windows checks a
// program when it creates its process, so one Smart App Control or
// another application control policy won't run fails here, and none of
// one it will run runs.
func trialStart(path string) error {
	cmd := proc.Command(path)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= suspended | noWindow
	if err := cmd.Start(); err != nil {
		return err
	}
	cmd.Process.Kill()
	cmd.Wait()
	return nil
}
