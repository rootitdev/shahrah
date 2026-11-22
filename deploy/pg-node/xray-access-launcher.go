// PasarGuard Node Xray launcher: restore log.access then exec the real core.
// The official node image has no Python; this static binary runs inside the container.
//
// Build (linux amd64):
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o xray-access-launcher ./deploy/pg-node
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func ensureFile(path string) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err == nil {
		_ = f.Close()
	}
}

func inject(raw []byte, access, errLog string) []byte {
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return raw
	}
	logObj, _ := cfg["log"].(map[string]any)
	if logObj == nil {
		logObj = map[string]any{}
		cfg["log"] = logObj
	}
	logObj["access"] = access
	if v, ok := logObj["error"]; !ok || v == nil || v == "" {
		logObj["error"] = errLog
	}
	if _, ok := logObj["loglevel"]; !ok {
		logObj["loglevel"] = "warning"
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return raw
	}
	return out
}

func usesStdin(args []string) bool {
	if len(args) == 0 {
		return true
	}
	for _, a := range args {
		if a == "stdin:" || strings.HasSuffix(a, "stdin:") {
			return true
		}
	}
	return false
}

func replaceStdinArg(args []string, path string) []string {
	out := make([]string, len(args))
	copy(out, args)
	replaced := false
	for i, a := range out {
		if a == "stdin:" || strings.HasSuffix(a, "stdin:") {
			out[i] = path
			replaced = true
		}
	}
	if !replaced {
		out = []string{"-c", path}
	}
	return out
}

func main() {
	realBin := env("XRAY_REAL", "/var/lib/pg-node/xray-core/xray.real")
	// Prefer paths on the pg-node bind-mount; /var/lib/shahrah is also mounted
	// by deploy/pg-node/docker-compose.yml for host tools (sni-watch).
	access := env("XRAY_ACCESS_LOG", "/var/lib/pg-node/logs/access.log")
	errLog := env("XRAY_ERROR_LOG", "/var/lib/pg-node/logs/error.log")
	ensureFile(access)
	ensureFile(errLog)

	args := os.Args[1:]
	if !usesStdin(args) {
		argv := append([]string{realBin}, args...)
		if err := syscall.Exec(realBin, argv, os.Environ()); err != nil {
			fmt.Fprintf(os.Stderr, "xray-access-launcher: exec %s: %v\n", realBin, err)
			os.Exit(127)
		}
	}

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xray-access-launcher: read stdin: %v\n", err)
		os.Exit(1)
	}
	raw = inject(raw, access, errLog)

	// Temp file under the bind-mount (large cores exceed pipe capacity; pipe+exec races).
	tmpDir := "/var/lib/pg-node/tmp"
	_ = os.MkdirAll(tmpDir, 0o755)
	tmp, err := os.CreateTemp(tmpDir, "xray-cfg-*.json")
	if err != nil {
		tmp, err = os.CreateTemp("", "xray-cfg-*.json")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "xray-access-launcher: tempfile: %v\n", err)
		os.Exit(1)
	}
	cfgPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(cfgPath)
		fmt.Fprintf(os.Stderr, "xray-access-launcher: write cfg: %v\n", err)
		os.Exit(1)
	}
	_ = tmp.Close()
	_ = os.Chmod(cfgPath, 0o600)

	newArgs := replaceStdinArg(args, cfgPath)
	argv := append([]string{realBin}, newArgs...)
	if err := syscall.Exec(realBin, argv, os.Environ()); err != nil {
		_ = os.Remove(cfgPath)
		fmt.Fprintf(os.Stderr, "xray-access-launcher: exec %s: %v\n", realBin, err)
		os.Exit(127)
	}
}
