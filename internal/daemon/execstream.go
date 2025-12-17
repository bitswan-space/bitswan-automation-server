package daemon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

// streamExecCmdNDJSON runs cmd and streams stdout/stderr as NDJSON log entries to w.
// It returns the command's exit error (if any).
func streamExecCmdNDJSON(ctx context.Context, w io.Writer, cmd *exec.Cmd) error {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = WriteLogEntry(w, "error", fmt.Sprintf("failed to create stdout pipe: %v", err))
		return err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = WriteLogEntry(w, "error", fmt.Sprintf("failed to create stderr pipe: %v", err))
		return err
	}

	if err := cmd.Start(); err != nil {
		_ = WriteLogEntry(w, "error", fmt.Sprintf("failed to start command: %v", err))
		return err
	}

	// Kill process if request is cancelled / client disconnects
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		streamLinesAsNDJSON(w, stdoutPipe, "info")
	}()

	go func() {
		defer wg.Done()
		streamLinesAsNDJSON(w, stderrPipe, "error")
	}()

	wg.Wait()
	close(done)

	if err := cmd.Wait(); err != nil {
		_ = WriteLogEntry(w, "error", fmt.Sprintf("command failed: %v", err))
		return err
	}

	return nil
}

func streamLinesAsNDJSON(w io.Writer, r io.Reader, level string) {
	scanner := bufio.NewScanner(r)
	// Allow long lines (some commands can emit long JSON/YAML)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	for scanner.Scan() {
		_ = WriteLogEntry(w, level, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		_ = WriteLogEntry(w, "error", fmt.Sprintf("stream read error: %v", err))
	}
}


