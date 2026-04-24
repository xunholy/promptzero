// cliprobe: minimal pty driver that sends ONE prompt and dumps every byte
// the CLI emits for 60s. Diagnoses why cliyolo got 0 bytes per prompt.
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/creack/pty"
)

func main() {
	cmd := exec.Command("./bin/promptzero", "--yolo", "--persona", "red-team-day", "--port", "/dev/ttyACM0")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	tty, err := pty.Start(cmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pty:", err)
		os.Exit(1)
	}
	defer tty.Close()
	defer cmd.Process.Kill()

	// Stream everything that comes back, with byte counts.
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := tty.Read(buf)
			if n > 0 {
				fmt.Fprintf(os.Stderr, "\n[+%d bytes @ %s]\n", n, time.Now().Format("15:04:05.000"))
				_, _ = io.Copy(os.Stdout, &readerFromBytes{b: buf[:n]})
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "read err:", err)
				return
			}
		}
	}()

	// Wait 25s for the banner + agent ready
	time.Sleep(25 * time.Second)

	// Send ONE prompt
	prompt := "Get the Flipper device info using device_info.\r"
	fmt.Fprintf(os.Stderr, "\n=== sending prompt: %q ===\n", prompt)
	tty.Write([]byte(prompt))

	// Wait 90s and watch what arrives
	time.Sleep(90 * time.Second)
	fmt.Fprintf(os.Stderr, "\n=== sending /quit ===\n")
	tty.Write([]byte("/quit\r"))
	time.Sleep(2 * time.Second)
}

type readerFromBytes struct{ b []byte }

func (r *readerFromBytes) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
