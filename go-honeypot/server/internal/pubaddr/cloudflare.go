package pubaddr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Cloudflare support. A domain you already own is the only way to get a
// hostname that survives an address change *and* can be automated end to
// end, so it gets a first-class client rather than a URL template: the API
// takes a JSON PATCH with a bearer token, discovers the zone and record by
// name, and creates the record when it does not exist yet.
//
// Token scope: Zone → DNS → Edit, restricted to the one zone.

const cfAPI = "https://api.cloudflare.com/client/v4"

type cfResponse struct {
	Success bool              `json:"success"`
	Errors  []cfError         `json:"errors"`
	Result  json.RawMessage   `json:"result"`
	Msgs    []json.RawMessage `json:"messages"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func (e cfError) String() string { return fmt.Sprintf("%d %s", e.Code, e.Message) }

func cfErrText(errs []cfError) string {
	if len(errs) == 0 {
		return "unknown error"
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, e.String())
	}
	return strings.Join(parts, "; ")
}

// updateCloudflare points the configured hostname at ip, creating the A
// record if it is missing. Zone and record ids are cached on the tracker so
// the steady state is a single PATCH every interval.
func (t *Tracker) updateCloudflare(ctx context.Context, ip string) (string, int) {
	host := t.Hostname()
	token := t.token()
	if host == "" {
		return "error: dyndns.hostname is required for cloudflare", 0
	}
	if token == "" {
		return "error: cloudflare needs an API token (dyndns.token or the credentials file)", 0
	}

	zone := t.cfg.Zone
	if zone == "" {
		// "hp.example.com" → "example.com". Multi-label TLDs (co.uk) need
		// the zone spelled out.
		parts := strings.Split(host, ".")
		if len(parts) < 2 {
			return "error: cannot infer zone from " + host + "; set dyndns.zone", 0
		}
		zone = strings.Join(parts[len(parts)-2:], ".")
	}

	t.mu.RLock()
	zoneID, recordID := t.cfZoneID, t.cfRecordID
	t.mu.RUnlock()

	if zoneID == "" {
		id, status, err := t.cfZoneLookup(ctx, token, zone)
		if err != nil {
			return "error: " + err.Error(), status
		}
		zoneID = id
		t.mu.Lock()
		t.cfZoneID = id
		t.mu.Unlock()
	}

	if recordID == "" {
		id, current, status, err := t.cfRecordLookup(ctx, token, zoneID, host)
		if err != nil {
			return "error: " + err.Error(), status
		}
		if id == "" {
			// No record yet: create it rather than making the operator do it.
			newID, status, err := t.cfCreateRecord(ctx, token, zoneID, host, ip)
			if err != nil {
				return "error: " + err.Error(), status
			}
			t.mu.Lock()
			t.cfRecordID = newID
			t.mu.Unlock()
			return "ok (record created)", status
		}
		recordID = id
		t.mu.Lock()
		t.cfRecordID = id
		t.mu.Unlock()
		if current == ip {
			return "nochg", 200
		}
	}

	status, err := t.cfPatchRecord(ctx, token, zoneID, recordID, host, ip)
	if err != nil {
		// A deleted or recreated record invalidates the cached id; forget it
		// so the next tick rediscovers instead of failing forever.
		t.mu.Lock()
		t.cfRecordID = ""
		t.mu.Unlock()
		return "error: " + err.Error(), status
	}
	return "ok", status
}

func (t *Tracker) cfDo(ctx context.Context, method, url, token string, body any) (*cfResponse, int, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "honeystack-pubaddr/1")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	var parsed cfResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 120))
	}
	if !parsed.Success {
		return &parsed, resp.StatusCode, fmt.Errorf("cloudflare: %s", cfErrText(parsed.Errors))
	}
	return &parsed, resp.StatusCode, nil
}

func (t *Tracker) cfZoneLookup(ctx context.Context, token, zone string) (string, int, error) {
	resp, status, err := t.cfDo(ctx, http.MethodGet, cfAPI+"/zones?name="+zone, token, nil)
	if err != nil {
		return "", status, err
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return "", status, err
	}
	if len(zones) == 0 {
		return "", status, fmt.Errorf("zone %q not found for this token", zone)
	}
	return zones[0].ID, status, nil
}

// cfRecordLookup returns the record id and its current content, or "" when
// the record does not exist yet.
func (t *Tracker) cfRecordLookup(ctx context.Context, token, zoneID, host string) (string, string, int, error) {
	url := fmt.Sprintf("%s/zones/%s/dns_records?type=A&name=%s", cfAPI, zoneID, host)
	resp, status, err := t.cfDo(ctx, http.MethodGet, url, token, nil)
	if err != nil {
		return "", "", status, err
	}
	var records []cfRecord
	if err := json.Unmarshal(resp.Result, &records); err != nil {
		return "", "", status, err
	}
	if len(records) == 0 {
		return "", "", status, nil
	}
	return records[0].ID, records[0].Content, status, nil
}

func (t *Tracker) cfCreateRecord(ctx context.Context, token, zoneID, host, ip string) (string, int, error) {
	url := fmt.Sprintf("%s/zones/%s/dns_records", cfAPI, zoneID)
	// A short TTL is the point of dynamic DNS; proxying would hide the host
	// behind Cloudflare, which is the opposite of what a honeypot wants.
	body := cfRecord{Type: "A", Name: host, Content: ip, TTL: 60, Proxied: false}
	resp, status, err := t.cfDo(ctx, http.MethodPost, url, token, body)
	if err != nil {
		return "", status, err
	}
	var created cfRecord
	if err := json.Unmarshal(resp.Result, &created); err != nil {
		return "", status, err
	}
	return created.ID, status, nil
}

func (t *Tracker) cfPatchRecord(ctx context.Context, token, zoneID, recordID, host, ip string) (int, error) {
	url := fmt.Sprintf("%s/zones/%s/dns_records/%s", cfAPI, zoneID, recordID)
	body := cfRecord{Type: "A", Name: host, Content: ip, TTL: 60, Proxied: false}
	_, status, err := t.cfDo(ctx, http.MethodPatch, url, token, body)
	return status, err
}
