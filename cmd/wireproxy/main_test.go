package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/windtf/wireproxy"
	"golang.zx2c4.com/wireguard/device"
)

func TestLogLevels(t *testing.T) {
	tests := []struct {
		level      string
		silent     bool
		wantApp    wireproxy.LogLevel
		wantDevice int
	}{
		{"error", false, wireproxy.LogError, device.LogLevelError},
		{"info", false, wireproxy.LogInfo, device.LogLevelError},
		{"debug", false, wireproxy.LogDebug, device.LogLevelVerbose},
		{"info", true, wireproxy.LogError, device.LogLevelError},
		{"debug", true, wireproxy.LogError, device.LogLevelError},
	}

	for _, tt := range tests {
		app, dev := logLevels(tt.level, tt.silent)
		if app != tt.wantApp || dev != tt.wantDevice {
			t.Errorf("logLevels(%q, %v) = %d, %d; want %d, %d", tt.level, tt.silent, app, dev, tt.wantApp, tt.wantDevice)
		}
	}
}

// TestHelperMain runs main() in a child process with the arguments in
// WIREPROXY_TEST_ARGS, so tests can observe its exit status and output.
func TestHelperMain(t *testing.T) {
	args, ok := os.LookupEnv("WIREPROXY_TEST_ARGS")
	if !ok {
		t.Skip("helper process only")
	}
	os.Args = append([]string{"wireproxy"}, strings.Fields(args)...)
	main()
	os.Exit(0)
}

func runMain(t *testing.T, args string, env ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMain$")
	cmd.Env = append(append(os.Environ(), "WIREPROXY_TEST_ARGS="+args), env...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errOut.String()
}

func TestUsageErrorExitsNonZero(t *testing.T) {
	for _, args := range []string{"--bogus", "-i", "--log-level loud"} {
		code, stdout, stderr := runMain(t, args)
		if code != 2 {
			t.Errorf("%q: exit code = %d, want 2", args, code)
		}
		if !strings.Contains(stderr, "usage: wireproxy") {
			t.Errorf("%q: usage not printed to stderr: %q", args, stderr)
		}
		if strings.Contains(stdout, "usage: wireproxy") {
			t.Errorf("%q: usage printed to stdout: %q", args, stdout)
		}
	}
}

const testConfig = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:51820
`

func writeTestConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wireproxy.conf")
	if err := os.WriteFile(path, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// freeAddr returns a loopback address that was free a moment ago. The caller
// must tolerate another process taking it before use.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// startChild starts main() in a child process and returns once its health
// endpoint answers, which happens after the signal handler is installed. ok is
// false if the child exited first, for example because another process took
// the port between freeAddr and the child's bind.
func startChild(t *testing.T, path, addr string) (cmd *exec.Cmd, done chan error, stderr *bytes.Buffer, ok bool) {
	t.Helper()
	cmd = exec.Command(os.Args[0], "-test.run=^TestHelperMain$")
	cmd.Env = append(os.Environ(), "WIREPROXY_TEST_ARGS=-s -c "+path+" -i "+addr)
	stderr = &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	done = make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-done:
			done <- err
			return cmd, done, stderr, false
		default:
		}
		resp, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			return cmd, done, stderr, true
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("child never became ready: %v\n%s", err, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSIGTERMShutsDownCleanly(t *testing.T) {
	path := writeTestConfig(t)

	var (
		cmd    *exec.Cmd
		done   chan error
		stderr *bytes.Buffer
		ok     bool
	)
	for attempt := 0; attempt < 3 && !ok; attempt++ {
		cmd, done, stderr, ok = startChild(t, path, freeAddr(t))
	}
	if !ok {
		t.Fatalf("child never started: %s", stderr.String())
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("child did not exit cleanly on SIGTERM: %v\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child did not exit after SIGTERM")
	}
}

func TestHelpExitsZero(t *testing.T) {
	code, stdout, _ := runMain(t, "--help")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "usage: wireproxy") {
		t.Errorf("help not printed to stdout: %q", stdout)
	}
}

func TestMissingConfigIsUsageError(t *testing.T) {
	// An empty HOME hides any default config under $HOME/.config.
	code, stdout, stderr := runMain(t, "", "HOME="+t.TempDir())
	if _, err := os.Stat("/etc/wireproxy/wireproxy.conf"); err == nil {
		t.Skip("a default config exists on this machine")
	}
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "configuration path is required") || !strings.Contains(stderr, "usage: wireproxy") {
		t.Errorf("stderr = %q", stderr)
	}
	if stdout != "" {
		t.Errorf("unexpected stdout: %q", stdout)
	}
}

func TestUnreadableConfigExitsOne(t *testing.T) {
	code, _, stderr := runMain(t, "-c "+filepath.Join(t.TempDir(), "missing.conf"))
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestInfoListenFailureExitsOne(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	code, _, stderr := runMain(t, "-c "+writeTestConfig(t)+" -i "+l.Addr().String())
	if code != 1 {
		t.Errorf("exit code = %d, want 1\n%s", code, stderr)
	}
	if strings.Contains(stderr, "goroutine ") {
		t.Errorf("stack trace printed: %s", stderr)
	}
}

func TestValidateInfoAddr(t *testing.T) {
	for _, addr := range []string{"", "127.0.0.1:9080", ":9080", "[::1]:9080", "localhost:0"} {
		if err := validateInfoAddr([]string{addr}); err != nil {
			t.Errorf("%q: unexpected error: %v", addr, err)
		}
	}
	for _, addr := range []string{"nohostport", "9080", "host:", "host:abc", "host:65536", "host:-1"} {
		if err := validateInfoAddr([]string{addr}); err == nil {
			t.Errorf("%q: expected an error", addr)
		}
	}
}

func TestMalformedInfoAddrIsUsageError(t *testing.T) {
	path := writeTestConfig(t)
	for _, addr := range []string{"nohostport", "127.0.0.1:http", "127.0.0.1:70000"} {
		code, _, stderr := runMain(t, "-c "+path+" -i "+addr)
		if code != 2 {
			t.Errorf("%q: exit code = %d, want 2", addr, code)
		}
		if !strings.Contains(stderr, "usage: wireproxy") || strings.Contains(stderr, "panic") {
			t.Errorf("%q: stderr = %q", addr, stderr)
		}
	}
}

func ruleStrings(rules []landlock.Rule) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		out[fmt.Sprint(r)] = true
	}
	return out
}

func TestNetworkRules(t *testing.T) {
	domains := []*regexp.Regexp{regexp.MustCompile(`^example\.com$`)}
	info := "127.0.0.1:9000"

	tests := []struct {
		name            string
		sections        []wireproxy.RoutineSpawner
		systemDNS       bool
		restrictConnect bool
		want            []string
		notWant         []string
	}{
		{
			name: "tunnel only with DNS restricts connect",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.HTTPConfig{BindAddress: "127.0.0.1:8080"},
				&wireproxy.TCPServerTunnelConfig{ListenPort: 1, Target: "10.0.0.1:5432"},
				&wireproxy.TCPClientTunnelConfig{BindAddress: &net.TCPAddr{Port: 2222}},
			},
			restrictConnect: true,
			want: []string{
				"ALLOW {bind_tcp} on TCP port 9000",
				"ALLOW {bind_tcp} on TCP port 8080",
				"ALLOW {bind_tcp} on TCP port 2222",
				"ALLOW {connect_tcp} on TCP port 5432",
				"ALLOW {connect_tcp} on TCP port 53",
			},
		},
		{
			name: "split routing HTTP restricts bind only",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.HTTPConfig{BindAddress: "127.0.0.1:8080", TunnelDomains: domains},
				&wireproxy.TCPServerTunnelConfig{ListenPort: 1, Target: "10.0.0.1:5432"},
			},
			want:    []string{"ALLOW {bind_tcp} on TCP port 8080", "ALLOW {bind_tcp} on TCP port 9000"},
			notWant: []string{"ALLOW {connect_tcp} on TCP port 5432", "ALLOW {connect_tcp} on TCP port 53"},
		},
		{
			name: "split routing SOCKS5 restricts bind only",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.Socks5Config{BindAddress: "127.0.0.1:1080", TunnelDomains: domains},
			},
			want:    []string{"ALLOW {bind_tcp} on TCP port 1080"},
			notWant: []string{"ALLOW {connect_tcp} on TCP port 53"},
		},
		{
			name: "split routing SNI restricts bind only",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.SNIConfig{BindAddress: "127.0.0.1:8443", TunnelDomains: domains},
			},
			want:    []string{"ALLOW {bind_tcp} on TCP port 8443"},
			notWant: []string{"ALLOW {connect_tcp} on TCP port 53"},
		},
		{
			name: "system DNS restricts bind only",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.Socks5Config{BindAddress: "127.0.0.1:1080"},
				&wireproxy.TCPServerTunnelConfig{ListenPort: 1, Target: "10.0.0.1:5432"},
			},
			systemDNS: true,
			want:      []string{"ALLOW {bind_tcp} on TCP port 1080"},
			notWant:   []string{"ALLOW {connect_tcp} on TCP port 5432", "ALLOW {connect_tcp} on TCP port 53"},
		},
		{
			name: "logging without domains still tunnels everything",
			sections: []wireproxy.RoutineSpawner{
				&wireproxy.HTTPConfig{BindAddress: "127.0.0.1:8080", LogDomains: true},
			},
			restrictConnect: true,
			want:            []string{"ALLOW {connect_tcp} on TCP port 53"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, restrictConnect := networkRules(tt.sections, &info, tt.systemDNS)
			if restrictConnect != tt.restrictConnect {
				t.Fatalf("restrictConnect = %v, want %v", restrictConnect, tt.restrictConnect)
			}
			got := ruleStrings(rules)
			for _, w := range tt.want {
				if !got[w] {
					t.Errorf("missing rule %q in %v", w, got)
				}
			}
			for _, w := range tt.notWant {
				if got[w] {
					t.Errorf("unexpected rule %q", w)
				}
			}
		})
	}
}

func TestResolverFiles(t *testing.T) {
	have := map[string]bool{}
	for _, f := range resolverFiles {
		have[f] = true
	}
	for _, f := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"} {
		if !have[f] {
			t.Errorf("%s is not readable after lockdown", f)
		}
	}
}
