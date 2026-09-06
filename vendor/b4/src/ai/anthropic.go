package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
)

const anthropicAPIVersion = "2023-06-01"

type anthropicProvider struct {
	endpoint string
	apiKey   string
	model    string
	httpc    *http.Client
	req      config.AIConfig
}

func (p *anthropicProvider) Name() string { return ProviderAnthropic }

type anthropicModelList struct {
	Data []struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		CreatedAt   string `json:"created_at"`
	} `json:"data"`
}

func (p *anthropicProvider) ListModels(ctx context.Context) ([]Model, error) {
	url := strings.TrimRight(p.endpoint, "/") + "/models?limit=100"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := p.httpc.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, readErrorBody(resp, "anthropic")
	}
	var list anthropicModelList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("anthropic: decode models: %w", err)
	}
	out := make([]Model, 0, len(list.Data))
	for _, m := range list.Data {
		var created int64
		if m.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, m.CreatedAt); err == nil {
				created = t.Unix()
			}
		}
		out = append(out, Model{ID: m.ID, DisplayName: m.DisplayName, Created: created})
	}
	return out, nil
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature *float64           `json:"temperature,omitempty"`
	Stream      bool               `json:"stream"`
}

type anthropicEvent struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta struct {
		Type       string `json:"type"`
		Text       string `json:"text"`
		StopReason string `json:"stop_reason"`
	} `json:"delta"`
	Message struct {
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (p *anthropicProvider) Stream(ctx context.Context, req Request) (<-chan Chunk, error) {
	msgs := make([]anthropicMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := string(m.Role)
		if role == string(RoleSystem) {
			continue
		}
		msgs = append(msgs, anthropicMessage{Role: role, Content: m.Content})
	}

	url := strings.TrimRight(p.endpoint, "/") + "/messages"
	makeReq := func(omitTemperature bool) (*http.Request, error) {
		body := anthropicRequest{
			Model:     p.model,
			System:    req.System,
			Messages:  msgs,
			MaxTokens: clampMaxTokens(req, 1024),
			Stream:    true,
		}
		if !omitTemperature {
			t := clampTemperature(req)
			body.Temperature = &t
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "text/event-stream")
		httpReq.Header.Set("x-api-key", p.apiKey)
		httpReq.Header.Set("anthropic-version", anthropicAPIVersion)
		return httpReq, nil
	}

	resp, err := postWithTemperatureRetry(ctx, p.httpc, makeReq, "anthropic")
	if err != nil {
		return nil, err
	}

	out := make(chan Chunk, 16)
	go func() {
		defer resp.Body.Close()
		defer close(out)
		usage := Usage{}
		parseSSE(ctx, resp.Body, out, func(payload []byte) (Chunk, bool, bool) {
			var ev anthropicEvent
			if err := json.Unmarshal(payload, &ev); err != nil {
				return Chunk{Err: fmt.Errorf("anthropic: bad event: %w", err)}, true, false
			}
			switch ev.Type {
			case "message_start":
				if ev.Message.Usage.InputTokens > 0 {
					usage.InputTokens = ev.Message.Usage.InputTokens
				}
				return Chunk{}, false, false
			case "content_block_delta":
				if ev.Delta.Type == "text_delta" && ev.Delta.Text != "" {
					return Chunk{Delta: ev.Delta.Text}, true, false
				}
				return Chunk{}, false, false
			case "message_delta":
				if ev.Usage.OutputTokens > 0 {
					usage.OutputTokens = ev.Usage.OutputTokens
				}
				return Chunk{}, false, false
			case "message_stop":
				u := usage
				return Chunk{Done: true, Usage: &u}, true, true
			case "error":
				msg := strings.TrimSpace(ev.Error.Message)
				kind := strings.TrimSpace(ev.Error.Type)
				switch {
				case msg != "" && kind != "":
					return Chunk{Err: fmt.Errorf("anthropic: %s: %s", kind, msg)}, true, true
				case msg != "":
					return Chunk{Err: fmt.Errorf("anthropic: %s", msg)}, true, true
				case kind != "":
					return Chunk{Err: fmt.Errorf("anthropic: %s", kind)}, true, true
				default:
					return Chunk{Err: fmt.Errorf("anthropic: stream error")}, true, true
				}
			default:
				return Chunk{}, false, false
			}
		})
	}()
	return out, nil
}
