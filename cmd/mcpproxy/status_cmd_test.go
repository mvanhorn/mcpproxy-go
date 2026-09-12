package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/config"
	"gopkg.in/yaml.v3"
)

func TestStatusMaskAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal 64-char key",
			input:    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			expected: "a1b2****a1b2",
		},
		{
			name:     "short key 8 chars",
			input:    "12345678",
			expected: "****",
		},
		{
			name:     "very short key",
			input:    "abc",
			expected: "****",
		},
		{
			name:     "empty key",
			input:    "",
			expected: "****",
		},
		{
			name:     "9-char key (just over threshold)",
			input:    "123456789",
			expected: "1234****6789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusMaskAPIKey(tt.input)
			if result != tt.expected {
				t.Errorf("statusMaskAPIKey(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestStatusBuildWebUIURL(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
		apiKey     string
		expected   string
	}{
		{
			name:       "normal address with key",
			listenAddr: "127.0.0.1:8080",
			apiKey:     "testkey123",
			expected:   "http://127.0.0.1:8080/ui/?apikey=testkey123",
		},
		{
			name:       "port-only address",
			listenAddr: ":8080",
			apiKey:     "testkey123",
			expected:   "http://127.0.0.1:8080/ui/?apikey=testkey123",
		},
		{
			name:       "custom port",
			listenAddr: "192.168.1.100:9090",
			apiKey:     "abc",
			expected:   "http://192.168.1.100:9090/ui/?apikey=abc",
		},
		{
			name:       "empty API key",
			listenAddr: "127.0.0.1:8080",
			apiKey:     "",
			expected:   "http://127.0.0.1:8080/ui/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusBuildWebUIURL(tt.listenAddr, tt.apiKey)
			if result != tt.expected {
				t.Errorf("statusBuildWebUIURL(%q, %q) = %q, want %q", tt.listenAddr, tt.apiKey, result, tt.expected)
			}
		})
	}
}

func TestStatusMaskWebUIURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		keys    []string
		invalid bool
	}{
		{name: "long key", input: "http://localhost/ui/?apikey=123456789abcdef", keys: []string{"1234****cdef"}},
		{name: "short key", input: "http://localhost/ui/?apikey=12345678", keys: []string{"****"}},
		{name: "encoded key and parameter name", input: "https://localhost/ui/?api%6bey=%61bcd%2Bsecret%2Ftail", keys: []string{"abcd****tail"}},
		{name: "repeated keys", input: "http://localhost/ui/?apikey=first-long-secret&apikey=short&apikey=", keys: []string{"firs****cret", "****", "****"}},
		{name: "empty key", input: "http://localhost/ui/?apikey=", keys: []string{"****"}},
		{name: "bare key", input: "http://localhost/ui/?apikey", keys: []string{"****"}},
		{name: "custom URL", input: "https://console.example:9443/custom%20path/ui?theme=dark&apikey=remote-long-secret&next=%2Fa%3Fb%3Dc&tag=a&tag=b#settings", keys: []string{"remo****cret"}},
		{name: "no key", input: "https://console.example/custom/ui?z=%20&a=1#settings"},
		{name: "empty URL", input: ""},
		{name: "invalid URL escape", input: "https://localhost/%zz?apikey=raw-secret-credential", invalid: true},
		{name: "invalid key escape", input: "https://localhost/ui?apikey=raw-secret-credential%zz", invalid: true},
		{name: "invalid unrelated query escape", input: "https://localhost/ui?apikey=raw-secret-credential&next=%zz", invalid: true},
		{name: "invalid query separator", input: "https://localhost/ui?apikey=raw-secret-credential;other=value", invalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := statusMaskWebUIURL(tt.input)
			if tt.invalid {
				if got != "" {
					t.Errorf("invalid display URL must be empty, got %q", got)
				}
				return
			}
			if tt.keys == nil && got != tt.input {
				t.Errorf("credential-free URL changed: got %q, want %q", got, tt.input)
			}
			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			query, err := url.ParseQuery(parsed.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(query["apikey"], tt.keys) {
				t.Errorf("masked keys = %q, want %q", query["apikey"], tt.keys)
			}
			original, err := url.Parse(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			originalQuery := original.Query()
			delete(query, "apikey")
			delete(originalQuery, "apikey")
			if !reflect.DeepEqual(query, originalQuery) {
				t.Errorf("unrelated query changed: got %v, want %v", query, originalQuery)
			}
			original.RawQuery, parsed.RawQuery = "", ""
			if *original != *parsed {
				t.Errorf("URL components changed: got %s, want %s", parsed, original)
			}
		})
	}
}

func TestCollectStatusFromConfig(t *testing.T) {
	cfg := &config.Config{
		Listen: "127.0.0.1:8080",
		APIKey: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
	}

	info := collectStatusFromConfig(cfg, "/tmp/test.sock", "/tmp/test/mcp_config.json")

	if info.State != "Not running" {
		t.Errorf("expected State 'Not running', got %q", info.State)
	}

	if !strings.Contains(info.ListenAddr, "(configured)") {
		t.Errorf("expected ListenAddr to contain '(configured)', got %q", info.ListenAddr)
	}

	if info.APIKey != cfg.APIKey {
		t.Errorf("expected APIKey to match config, got %q", info.APIKey)
	}

	if info.ConfigPath != "/tmp/test/mcp_config.json" {
		t.Errorf("expected ConfigPath '/tmp/test/mcp_config.json', got %q", info.ConfigPath)
	}

	if !strings.Contains(info.WebUIURL, "apikey=") {
		t.Errorf("expected WebUIURL to contain apikey, got %q", info.WebUIURL)
	}

	if info.Servers != nil {
		t.Error("expected Servers to be nil for config-only mode")
	}

	if info.Uptime != "" {
		t.Errorf("expected Uptime to be empty for config-only mode, got %q", info.Uptime)
	}
}

func TestCollectStatusFromConfigDefaults(t *testing.T) {
	cfg := &config.Config{
		APIKey: "testkey",
	}

	info := collectStatusFromConfig(cfg, "", "/tmp/config.json")

	if !strings.HasPrefix(info.ListenAddr, "127.0.0.1:8080") {
		t.Errorf("expected default listen addr 127.0.0.1:8080, got %q", info.ListenAddr)
	}
}

func TestFormatStatusTable(t *testing.T) {
	t.Run("running state", func(t *testing.T) {
		info := &StatusInfo{
			State:      "Running",
			ListenAddr: "127.0.0.1:8080",
			Uptime:     "2h 15m",
			APIKey:     "a1b2****a1b2",
			WebUIURL:   "http://127.0.0.1:8080/ui/?apikey=test",
			Servers:    &ServerCounts{Connected: 5, Quarantined: 1, Total: 6},
			SocketPath: "/tmp/mcpproxy.sock",
			Version:    "v1.0.0",
		}

		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		printStatusTable(info)

		w.Close()
		os.Stdout = old

		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		output := string(buf[:n])

		checks := []string{"MCPProxy Status", "Running", "127.0.0.1:8080", "2h 15m", "a1b2****a1b2", "5 connected, 1 quarantined", "/tmp/mcpproxy.sock", "v1.0.0"}
		for _, check := range checks {
			if !strings.Contains(output, check) {
				t.Errorf("expected output to contain %q, output:\n%s", check, output)
			}
		}
	})

	t.Run("not running state", func(t *testing.T) {
		info := &StatusInfo{
			State:      "Not running",
			ListenAddr: "127.0.0.1:8080 (configured)",
			APIKey:     "a1b2****a1b2",
			WebUIURL:   "http://127.0.0.1:8080/ui/?apikey=test",
			ConfigPath: "/home/user/.mcpproxy/mcp_config.json",
		}

		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		printStatusTable(info)

		w.Close()
		os.Stdout = old

		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		output := string(buf[:n])

		checks := []string{"Not running", "(configured)", "Config:"}
		for _, check := range checks {
			if !strings.Contains(output, check) {
				t.Errorf("expected output to contain %q, output:\n%s", check, output)
			}
		}

		// Should NOT contain server counts or socket
		if strings.Contains(output, "Servers:") {
			t.Error("should not contain Servers line when not running")
		}
	})
}

// Status command tests mutate command globals and must not run in parallel.
func setupStatusCommandTest(t *testing.T, daemon bool, webUIURL string) *config.Config {
	t.Helper()
	clearDaemonEnv(t)
	t.Setenv("MCPPROXY_OUTPUT", "")
	t.Setenv("MCPPROXY_LISTEN", "")
	t.Setenv("MCPPROXY_DATA", "")
	oldConfig, oldDataDir := configFile, dataDir
	oldFormat, oldJSON := globalOutputFormat, globalJSONOutput
	oldShow, oldWeb, oldReset := statusShowKey, statusWebURL, statusResetKey
	t.Cleanup(func() {
		configFile, dataDir = oldConfig, oldDataDir
		globalOutputFormat, globalJSONOutput = oldFormat, oldJSON
		statusShowKey, statusWebURL, statusResetKey = oldShow, oldWeb, oldReset
	})
	dataDir = t.TempDir()
	configFile = config.GetConfigPath(dataDir)
	globalJSONOutput = false
	cfg := config.DefaultConfig()
	cfg.Listen = "127.0.0.1:8080"
	cfg.DataDir = dataDir
	cfg.APIKey = "local-credential-0123456789abcdef"
	if err := config.SaveConfig(cfg, configFile); err != nil {
		t.Fatal(err)
	}
	// Read the saved key for each request so reset tests also verify that
	// transport authentication uses the newly persisted, unmasked key.
	cfgPath := configFile
	var statusRequests, infoRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Errorf("read fixture config: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var saved config.Config
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Errorf("decode fixture config: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if got := r.Header.Get("X-API-Key"); got != saved.APIKey {
			t.Errorf("authentication key = %q, want %q", got, saved.APIKey)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/status":
			statusRequests.Add(1)
			if !daemon {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"data":{"running":true,"listen_addr":"127.0.0.1:8080"}}`))
		case "/api/v1/info":
			infoRequests.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    map[string]interface{}{"web_ui_url": webUIURL},
			})
		default:
			t.Errorf("unexpected daemon request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(func() {
		server.Close()
		if statusRequests.Load() == 0 {
			t.Error("command did not probe the test daemon")
		}
		if daemon && infoRequests.Load() == 0 {
			t.Error("command did not collect the daemon URL")
		}
	})
	t.Setenv("MCPPROXY_TRAY_ENDPOINT", server.URL)
	return cfg
}

func readStatusTestConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return &cfg
}

func executeStatusTestCommand(t *testing.T, format string, args ...string) string {
	t.Helper()
	globalOutputFormat = format
	cmd := GetStatusCommand()
	cmd.SetArgs(args)
	var err error
	output := captureStdout(t, func() { err = cmd.Execute() })
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	return output
}

func decodeStatusTestOutput(t *testing.T, format, output string) StatusInfo {
	t.Helper()
	var info StatusInfo
	switch format {
	case "json":
		if err := json.Unmarshal([]byte(output), &info); err != nil {
			t.Fatal(err)
		}
	case "yaml":
		if err := yaml.Unmarshal([]byte(output), &info); err != nil {
			t.Fatal(err)
		}
	default:
		for _, line := range strings.Split(output, "\n") {
			label, value, _ := strings.Cut(strings.TrimSpace(line), ":")
			switch label {
			case "State":
				info.State = strings.TrimSpace(value)
			case "API Key":
				info.APIKey = strings.TrimSpace(value)
			case "Web UI":
				info.WebUIURL = strings.TrimSpace(value)
			}
		}
	}
	return info
}

func TestRunStatusCredentials(t *testing.T) {
	const daemonKey = "remote-credential-fedcba9876543210"
	const daemonURL = "https://console.example:9443/custom/ui?theme=dark&apikey=" + daemonKey + "#settings"
	for _, mode := range []string{"config", "daemon"} {
		for _, format := range []string{"table", "json", "yaml"} {
			for _, flag := range []string{"masked", "--show-key"} {
				t.Run(mode+"/"+format+"/"+flag, func(t *testing.T) {
					cfg := setupStatusCommandTest(t, mode == "daemon", daemonURL)
					rawURL := statusBuildWebUIURL(cfg.Listen, cfg.APIKey)
					urlKey, state := cfg.APIKey, "Not running"
					if mode == "daemon" {
						rawURL, urlKey, state = daemonURL, daemonKey, "Running"
					}
					var args []string
					if flag == "--show-key" {
						args = append(args, flag)
					}
					output := executeStatusTestCommand(t, format, args...)
					info := decodeStatusTestOutput(t, format, output)
					wantKey, wantURLKey := cfg.APIKey, urlKey
					if flag == "masked" {
						wantKey, wantURLKey = "loca****cdef", "loca****cdef"
						if mode == "daemon" {
							wantURLKey = "remo****3210"
						}
						for _, key := range []string{cfg.APIKey, urlKey} {
							if strings.Contains(output, key) {
								t.Errorf("ordinary status leaked full credential: %s", output)
							}
						}
					} else if info.WebUIURL != rawURL {
						t.Errorf("--show-key URL = %q, want %q", info.WebUIURL, rawURL)
					}
					if info.State != state || info.APIKey != wantKey {
						t.Errorf("state/key = %q/%q, want %q/%q", info.State, info.APIKey, state, wantKey)
					}
					parsed, err := url.Parse(info.WebUIURL)
					if err != nil {
						t.Fatal(err)
					}
					if got := parsed.Query().Get("apikey"); got != wantURLKey {
						t.Errorf("URL key = %q, want %q", got, wantURLKey)
					}
					if saved := readStatusTestConfig(t, configFile); saved.APIKey != cfg.APIKey {
						t.Errorf("ordinary status changed saved key to %q", saved.APIKey)
					}
				})
			}
		}
	}
}

func TestWebURLFlag(t *testing.T) {
	const daemonURL = "https://console.example/custom/ui?theme=dark&apikey=remote-credential#settings"
	for _, mode := range []string{"config", "daemon"} {
		for _, showKey := range []bool{false, true} {
			name := mode + "/web-url"
			if showKey {
				name += "/show-key"
			}
			t.Run(name, func(t *testing.T) {
				cfg := setupStatusCommandTest(t, mode == "daemon", daemonURL)
				want := statusBuildWebUIURL(cfg.Listen, cfg.APIKey)
				if mode == "daemon" {
					want = daemonURL
				}
				args := []string{"--web-url"}
				if showKey {
					args = append(args, "--show-key")
				}
				if got := executeStatusTestCommand(t, "json", args...); got != want+"\n" {
					t.Errorf("--web-url output = %q, want %q", got, want+"\n")
				}
			})
		}
	}
}

func TestRunStatusResetKey(t *testing.T) {
	for _, format := range []string{"table", "json", "yaml", "web-url"} {
		t.Run(format, func(t *testing.T) {
			cfg := setupStatusCommandTest(t, false, "")
			stderr, err := os.CreateTemp(t.TempDir(), "stderr")
			if err != nil {
				t.Fatal(err)
			}
			oldStderr := os.Stderr
			os.Stderr = stderr
			t.Cleanup(func() {
				os.Stderr = oldStderr
				_ = stderr.Close()
			})
			args := []string{"--reset-key"}
			if format == "web-url" {
				args = append(args, "--web-url")
			}
			output := executeStatusTestCommand(t, format, args...)
			saved := readStatusTestConfig(t, configFile)
			warnings, err := os.ReadFile(stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(warnings), "Warning: Resetting the API key") ||
				!strings.Contains(string(warnings), "New API key: "+saved.APIKey) {
				t.Errorf("reset notices missing from stderr: %s", warnings)
			}
			if strings.Contains(output, "Warning:") || strings.Contains(output, "New API key:") {
				t.Errorf("reset notices leaked to stdout: %s", output)
			}
			if saved.APIKey == cfg.APIKey || len(saved.APIKey) != 64 {
				t.Fatalf("reset did not persist a new 64-character key: %q", saved.APIKey)
			}
			wantURL := statusBuildWebUIURL(cfg.Listen, saved.APIKey)
			if format == "web-url" {
				if output != wantURL+"\n" {
					t.Errorf("reset URL output = %q, want %q", output, wantURL+"\n")
				}
				return
			}
			info := decodeStatusTestOutput(t, format, output)
			if info.APIKey != saved.APIKey || info.WebUIURL != wantURL {
				t.Errorf("reset output did not reveal the saved key in both fields: %s", output)
			}
		})
	}
}

func TestRunStatusInvalidWebUIURL(t *testing.T) {
	for _, rawURL := range []string{
		"https://console.example/%zz?apikey=raw-secret-credential",
		"https://console.example/ui?apikey=raw-secret-credential&other=%zz",
	} {
		for _, format := range []string{"table", "json", "yaml"} {
			t.Run(format+"/"+rawURL, func(t *testing.T) {
				setupStatusCommandTest(t, true, rawURL)
				output := executeStatusTestCommand(t, format)
				if strings.Contains(output, "raw-secret-credential") {
					t.Errorf("invalid URL leaked credential: %s", output)
				}
				info := decodeStatusTestOutput(t, format, output)
				if info.WebUIURL != "" {
					t.Errorf("invalid display URL = %q, want empty", info.WebUIURL)
				}
			})
		}
	}
}

func TestResetKey(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "mcp_config.json")

	cfg := &config.Config{
		Listen: "127.0.0.1:8080",
		APIKey: "old_key_1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
	}

	// Save initial config
	initialData, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configPath, initialData, 0600)

	oldKey := cfg.APIKey
	newKey, err := resetAPIKey(cfg, configPath)
	if err != nil {
		t.Fatalf("resetAPIKey failed: %v", err)
	}

	// Verify new key is different
	if newKey == oldKey {
		t.Error("new key should be different from old key")
	}

	// Verify new key is 64 hex chars
	if len(newKey) != 64 {
		t.Errorf("expected 64-char hex key, got %d chars", len(newKey))
	}

	// Verify config file was updated
	fileData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}
	if !strings.Contains(string(fileData), newKey) {
		t.Error("config file should contain new key")
	}
}

func TestResetKeyWithEnvVar(t *testing.T) {
	// This tests the logic branch, not the actual env var check
	// The actual env var warning is printed in runStatus, which checks os.LookupEnv
	t.Run("env var detection", func(t *testing.T) {
		_, exists := os.LookupEnv("MCPPROXY_API_KEY")
		// Just verify the env check function works
		if exists {
			t.Log("MCPPROXY_API_KEY is set - env var warning would be shown")
		} else {
			t.Log("MCPPROXY_API_KEY is not set - no env var warning")
		}
	})
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"minutes only", "15m", "15m"},
		{"hours and minutes", "2h15m", "2h 15m"},
		{"days hours minutes", "49h30m", "2d 1h 30m"},
		{"zero", "0s", "0m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _ := parseTestDuration(tt.input)
			result := statusFormatDuration(d)
			if result != tt.expected {
				t.Errorf("statusFormatDuration(%v) = %q, want %q", d, result, tt.expected)
			}
		})
	}
}

func TestExtractServerCounts(t *testing.T) {
	// Real /api/v1/status upstream_stats shape (see internal/server/server.go
	// and internal/upstream/manager.go GetStats builders).
	stats := map[string]interface{}{
		"connected_servers":   float64(14),
		"quarantined_servers": float64(2),
		"total_servers":       float64(28),
	}

	counts := extractServerCounts(stats)

	if counts.Connected != 14 {
		t.Errorf("expected Connected=14, got %d", counts.Connected)
	}
	if counts.Quarantined != 2 {
		t.Errorf("expected Quarantined=2, got %d", counts.Quarantined)
	}
	if counts.Total != 28 {
		t.Errorf("expected Total=28, got %d", counts.Total)
	}
}

func TestExtractServerCountsLegacyKeys(t *testing.T) {
	// Older daemons emitted bare connected/quarantined/total keys.
	stats := map[string]interface{}{
		"connected":   float64(5),
		"quarantined": float64(2),
		"total":       float64(7),
	}

	counts := extractServerCounts(stats)

	if counts.Connected != 5 {
		t.Errorf("expected Connected=5, got %d", counts.Connected)
	}
	if counts.Quarantined != 2 {
		t.Errorf("expected Quarantined=2, got %d", counts.Quarantined)
	}
	if counts.Total != 7 {
		t.Errorf("expected Total=7, got %d", counts.Total)
	}
}

func TestExtractServerCountsNoTotal(t *testing.T) {
	stats := map[string]interface{}{
		"connected_servers":   float64(3),
		"quarantined_servers": float64(1),
	}

	counts := extractServerCounts(stats)

	if counts.Total != 4 {
		t.Errorf("expected Total=4 (sum), got %d", counts.Total)
	}
}

func TestStatusJSONOutput(t *testing.T) {
	info := &StatusInfo{
		State:      "Running",
		ListenAddr: "127.0.0.1:8080",
		APIKey:     "a1b2****a1b2",
		WebUIURL:   "http://127.0.0.1:8080/ui/?apikey=test",
		Servers:    &ServerCounts{Connected: 3, Quarantined: 0, Total: 3},
		Version:    "v1.0.0",
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printStatusJSON(info)

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("printStatusJSON failed: %v", err)
	}

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	var result StatusInfo
	if jsonErr := json.Unmarshal([]byte(output), &result); jsonErr != nil {
		t.Fatalf("invalid JSON: %v\nOutput: %s", jsonErr, output)
	}

	if result.State != "Running" {
		t.Errorf("expected state 'Running', got %q", result.State)
	}
	if result.Servers == nil {
		t.Fatal("expected servers in JSON output")
	}
	if result.Servers.Connected != 3 {
		t.Errorf("expected 3 connected, got %d", result.Servers.Connected)
	}
}

func TestStatusRoutingModeInTable(t *testing.T) {
	tests := []struct {
		name        string
		routingMode string
		expected    string
	}{
		{
			name:        "retrieve_tools mode",
			routingMode: "retrieve_tools",
			expected:    "retrieve_tools",
		},
		{
			name:        "direct mode",
			routingMode: "direct",
			expected:    "direct",
		},
		{
			name:        "code_execution mode",
			routingMode: "code_execution",
			expected:    "code_execution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &StatusInfo{
				State:       "Running",
				Edition:     "personal",
				ListenAddr:  "127.0.0.1:8080",
				APIKey:      "a1b2****a1b2",
				WebUIURL:    "http://127.0.0.1:8080/ui/?apikey=test",
				RoutingMode: tt.routingMode,
			}

			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			printStatusTable(info)

			w.Close()
			os.Stdout = old

			buf := make([]byte, 4096)
			n, _ := r.Read(buf)
			output := string(buf[:n])

			if !strings.Contains(output, "Routing:") {
				t.Errorf("expected output to contain 'Routing:', output:\n%s", output)
			}
			if !strings.Contains(output, tt.expected) {
				t.Errorf("expected output to contain %q, output:\n%s", tt.expected, output)
			}
		})
	}
}

func TestStatusRoutingModeInJSON(t *testing.T) {
	info := &StatusInfo{
		State:       "Running",
		Edition:     "personal",
		ListenAddr:  "127.0.0.1:8080",
		APIKey:      "testkey",
		WebUIURL:    "http://127.0.0.1:8080/ui/",
		RoutingMode: "direct",
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printStatusJSON(info)

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("printStatusJSON failed: %v", err)
	}

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	var result StatusInfo
	if jsonErr := json.Unmarshal([]byte(output), &result); jsonErr != nil {
		t.Fatalf("invalid JSON: %v\nOutput: %s", jsonErr, output)
	}

	if result.RoutingMode != "direct" {
		t.Errorf("expected routing_mode 'direct', got %q", result.RoutingMode)
	}
}

func TestCollectStatusFromConfigRoutingMode(t *testing.T) {
	t.Run("uses config routing mode", func(t *testing.T) {
		cfg := &config.Config{
			Listen:      "127.0.0.1:8080",
			APIKey:      "testkey",
			RoutingMode: "direct",
		}

		info := collectStatusFromConfig(cfg, "/tmp/test.sock", "/tmp/config.json")

		if info.RoutingMode != "direct" {
			t.Errorf("expected routing mode 'direct', got %q", info.RoutingMode)
		}
	})

	t.Run("defaults to retrieve_tools when empty", func(t *testing.T) {
		cfg := &config.Config{
			Listen: "127.0.0.1:8080",
			APIKey: "testkey",
		}

		info := collectStatusFromConfig(cfg, "/tmp/test.sock", "/tmp/config.json")

		if info.RoutingMode != config.RoutingModeRetrieveTools {
			t.Errorf("expected routing mode %q, got %q", config.RoutingModeRetrieveTools, info.RoutingMode)
		}
	})
}

// parseTestDuration is a helper to parse duration strings for tests.
func parseTestDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
