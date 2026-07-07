// Package probe queries the Wazuh indexer for live SIEM measurements.
// Credentials come from env vars only — never hardcoded.
package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// IndexerClient holds connection state for the Wazuh indexer.
type IndexerClient struct {
	URL    string
	User   string
	Pass   string
	client *http.Client
}

// AlertClient holds connection state for the Wazuh manager API.
type AlertClient struct {
	APIURL string
	User   string
	Pass   string
	client *http.Client
	token  string
}

// Evidence is a live-probed measurement row.
type Evidence struct {
	Rule                 string   `json:"rule"`
	State                string   `json:"state"`
	Liveness             string   `json:"liveness"`
	Volume               int      `json:"volume"`
	BaselineVolume       int      `json:"baseline_volume"`
	FieldPopulate        *float64 `json:"field_populate"`
	BaselineFieldPopulate float64  `json:"baseline_field_populate"`
	ProbeError           string   `json:"probe_error,omitempty"`
}

// NewIndexerClient creates a client from environment variables.
func NewIndexerClient() *IndexerClient {
	return &IndexerClient{
		URL:  getEnv("INDEXER_URL", "https://localhost:9200"),
		User: getEnv("INDEXER_USER", "admin"),
		Pass: os.Getenv("INDEXER_PASS"),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// NewAlertClient creates a client for the Wazuh manager API.
func NewAlertClient() *AlertClient {
	return &AlertClient{
		APIURL: getEnv("WAZUH_API_URL", "https://localhost:55000"),
		User:   getEnv("WAZUH_API_USER", "wazuh-wui"),
		Pass:   os.Getenv("WAZUH_API_PASS"),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (c *IndexerClient) do(method, path, body string) ([]byte, error) {
	req, err := http.NewRequest(method, strings.TrimRight(c.URL, "/")+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.User, c.Pass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (c *AlertClient) auth(ctx context.Context) error {
	if c.token != "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		strings.TrimRight(c.APIURL, "/")+"/security/user/authenticate?raw=true", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.User, c.Pass)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("wazuh api auth: %d %s", resp.StatusCode, string(data))
	}
	c.token = strings.TrimSpace(string(data))
	return nil
}

func (c *AlertClient) apiGet(ctx context.Context, path string) ([]byte, error) {
	if err := c.auth(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		strings.TrimRight(c.APIURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// AgentStatus returns the REAL agent status ONLY when the API call succeeds.
// "disconnected" from a successful API call is real source death.
// A failed API call returns an error — it is NOT "disconnected".
func (c *AlertClient) AgentStatus(ctx context.Context, agentID string) (string, error) {
	data, err := c.apiGet(ctx, "/agents?agents_list="+agentID+"&status=active")
	if err != nil {
		return "", fmt.Errorf("wazuh api unreachable: %w", err)
	}
	var resp struct {
		Data struct {
			AffectedItems []json.RawMessage `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("wazuh api decode: %w", err)
	}
	if len(resp.Data.AffectedItems) > 0 {
		return "active", nil
	}
	return "disconnected", nil
}

// EventVolume returns the count of event-type events from agent in the time window.
func (c *IndexerClient) EventVolume(agentID, eventTypeField string, eventID int, windowMinutes int) (int, error) {
	query := fmt.Sprintf(`{
		"query": {
			"bool": {
				"must": [
					{"term": {"agent.id": "%s"}},
					{"term": {"%s": "%d"}},
					{"range": {"@timestamp": {"gte": "now-%dm"}}}
				]
			}
		}
	}`, agentID, eventTypeField, eventID, windowMinutes)
	body, err := c.do("POST", "/wazuh-archives-*/_count", query)
	if err != nil {
		return 0, fmt.Errorf("indexer unreachable: %w", err)
	}
	var result struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("indexer decode: %w", err)
	}
	return result.Count, nil
}

// FieldPopulate returns the fraction of event-type events where fieldPath is non-null.
func (c *IndexerClient) FieldPopulate(agentID, eventTypeField string, eventID int, fieldPath string, windowMinutes int) (float64, error) {
	query := fmt.Sprintf(`{
		"query": {
			"bool": {
				"must": [
					{"term": {"agent.id": "%s"}},
					{"term": {"%s": "%d"}},
					{"range": {"@timestamp": {"gte": "now-%dm"}}}
				]
			}
		},
		"size": 0,
		"aggs": {
			"total": {"value_count": {"field": "%s"}},
			"populated": {"filter": {"exists": {"field": "%s"}}}
		}
	}`, agentID, eventTypeField, eventID, windowMinutes, eventTypeField, fieldPath)
	body, err := c.do("POST", "/wazuh-archives-*/_search", query)
	if err != nil {
		return 0, fmt.Errorf("indexer unreachable: %w", err)
	}
	var result struct {
		Aggregations struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Populated struct {
				DocCount int `json:"doc_count"`
			} `json:"populated"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("indexer decode: %w", err)
	}
	if result.Aggregations.Total.Value == 0 {
		return 0, nil
	}
	return float64(result.Aggregations.Populated.DocCount) / float64(result.Aggregations.Total.Value), nil
}

// ProbeAll gathers live evidence for a rule config.
// If ANY probe returns an error, ProbeError is set and no fabricated values are populated.
func ProbeAll(ctx context.Context, ic *IndexerClient, ac *AlertClient, cfg RuleConfig) Evidence {
	ev := Evidence{
		Rule:                 cfg.Rule,
		State:                "live",
		BaselineVolume:       cfg.BaselineVolume,
		BaselineFieldPopulate: cfg.BaselineFieldPopulate,
	}

	var errs []string

	status, err := ac.AgentStatus(ctx, cfg.AgentID)
	if err != nil {
		errs = append(errs, "liveness: "+err.Error())
	} else {
		ev.Liveness = status
	}

	vol, err := ic.EventVolume(cfg.AgentID, cfg.EventTypeField, cfg.EventID, cfg.WindowMinutes)
	if err != nil {
		errs = append(errs, "volume: "+err.Error())
	} else {
		ev.Volume = vol
	}

	fp, err := ic.FieldPopulate(cfg.AgentID, cfg.EventTypeField, cfg.EventID, cfg.FieldPath, cfg.WindowMinutes)
	if err != nil {
		errs = append(errs, "field: "+err.Error())
	} else {
		ev.FieldPopulate = &fp
	}

	if len(errs) > 0 {
		ev.ProbeError = strings.Join(errs, "; ")
	}
	return ev
}

// RuleConfig maps a detection rule to the SIEM fields needed to probe it.
type RuleConfig struct {
	Rule                  string  `yaml:"rule"`
	AgentID               string  `yaml:"agent_id"`
	EventTypeField        string  `yaml:"event_type_field"`
	EventID               int     `yaml:"event_id"`
	FieldPath             string  `yaml:"field_path"`
	RuleID                string  `yaml:"rule_id"`
	WindowMinutes         int     `yaml:"window_minutes"`
	BaselineVolume        int     `yaml:"baseline_volume"`
	BaselineFieldPopulate float64 `yaml:"baseline_field_populate"`
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
