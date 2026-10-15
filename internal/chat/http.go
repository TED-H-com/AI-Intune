package chat

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/channels"
)

type chatHuman struct {
	ID  json.Number `json:"id"`
	Bot bool        `json:"is_bot"`
}
type telegramMessage struct {
	From chatHuman `json:"from"`
	Chat struct {
		ID json.Number `json:"id"`
	} `json:"chat"`
	Text       string          `json:"text"`
	Date       int64           `json:"date"`
	ViaBot     json.RawMessage `json:"via_bot"`
	SenderChat json.RawMessage `json:"sender_chat"`
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	c, ok := e.configs[r.PathValue("id")]
	if !ok || !c.Enabled {
		http.NotFound(w, r)
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		http.Error(w, "invalid event", 400)
		return
	}
	var v event
	if c.Kind == "telegram" {
		if !channels.VerifyTelegram(e.secret(r.Context(), c.SecretRef), r.Header.Get("X-Telegram-Bot-Api-Secret-Token")) {
			http.Error(w, "unauthorized", 401)
			return
		}
		var update struct {
			ID       *int64           `json:"update_id"`
			Message  *telegramMessage `json:"message"`
			Callback *struct {
				ID      string          `json:"id"`
				From    chatHuman       `json:"from"`
				Data    string          `json:"data"`
				Message telegramMessage `json:"message"`
			} `json:"callback_query"`
		}
		if json.Unmarshal(raw, &update) != nil || update.ID == nil {
			http.Error(w, "invalid event", 400)
			return
		}
		v.id = strconv.FormatInt(*update.ID, 10)
		var m telegramMessage
		if update.Callback != nil {
			cb := update.Callback
			m = cb.Message
			v.user = string(cb.From.ID)
			v.bot = cb.From.Bot
			parseDecision(cb.Data, &v)
		} else if update.Message != nil {
			m = *update.Message
			v.user = string(m.From.ID)
			v.bot = m.From.Bot || len(m.ViaBot) > 0 || len(m.SenderChat) > 0
			v.command = m.Text
		} else {
			w.WriteHeader(204)
			return
		}
		v.destination = string(m.Chat.ID)
		at := time.Unix(m.Date, 0)
		if at.Before(e.now().Add(-10*time.Minute)) || at.After(e.now().Add(time.Minute)) {
			w.WriteHeader(204)
			return
		}
	} else if c.Kind == "discord" {
		if !channels.VerifyDiscord(e.secret(r.Context(), c.PublicKeyRef), r.Header.Get("X-Signature-Ed25519"), r.Header.Get("X-Signature-Timestamp"), raw, e.now(), 5*time.Minute) {
			http.Error(w, "unauthorized", 401)
			return
		}
		type human struct {
			ID  string `json:"id"`
			Bot bool   `json:"bot"`
		}
		var interaction struct {
			ID        string `json:"id"`
			Type      int    `json:"type"`
			ChannelID string `json:"channel_id"`
			User      human  `json:"user"`
			Member    struct {
				User human `json:"user"`
			} `json:"member"`
			Data struct {
				Name     string `json:"name"`
				CustomID string `json:"custom_id"`
				Options  []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"options"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &interaction) != nil {
			http.Error(w, "invalid event", 400)
			return
		}
		if interaction.Type == 1 {
			writeJSON(w, map[string]any{"type": 1})
			return
		}
		v.id = interaction.ID
		v.destination = interaction.ChannelID
		u := interaction.Member.User
		if u.ID == "" {
			u = interaction.User
		}
		v.user = u.ID
		v.bot = u.Bot
		switch interaction.Type {
		case 2:
			v.command = interaction.Data.Name
			if len(interaction.Data.Options) > 0 {
				if len(interaction.Data.Options) != 1 || interaction.Data.Options[0].Name != "alert_id" {
					w.WriteHeader(204)
					return
				}
				v.command += " " + interaction.Data.Options[0].Value
			}
		case 3:
			parseDecision(interaction.Data.CustomID, &v)
		default:
			w.WriteHeader(204)
			return
		}
	} else {
		http.NotFound(w, r)
		return
	}
	if v.user == "" || len(v.user) > 64 {
		w.WriteHeader(204)
		return
	}
	result := e.execute(r.Context(), c, v)
	if result.text == "" {
		w.WriteHeader(204)
		return
	}
	if c.Kind == "telegram" {
		payload := map[string]any{"method": "sendMessage", "chat_id": v.destination, "text": result.text, "disable_web_page_preview": true}
		if result.approval != "" {
			payload["reply_markup"] = map[string]any{"inline_keyboard": [][]map[string]string{{{"text": "Approve", "callback_data": "approve:" + result.approval}, {"text": "Deny", "callback_data": "deny:" + result.approval}}}}
		}
		writeJSON(w, payload)
	} else {
		data := map[string]any{"content": result.text, "flags": 64, "allowed_mentions": map[string]any{"parse": []string{}}}
		if result.approval != "" {
			data["flags"] = 0 // Approval cards are visible to other allowlisted humans in this destination.
			data["components"] = []any{map[string]any{"type": 1, "components": []any{map[string]any{"type": 2, "style": 3, "label": "Approve", "custom_id": "approve:" + result.approval}, map[string]any{"type": 2, "style": 4, "label": "Deny", "custom_id": "deny:" + result.approval}}}}
		}
		writeJSON(w, map[string]any{"type": 4, "data": data})
	}
}
func parseDecision(s string, v *event) {
	parts := strings.Split(s, ":")
	if len(parts) == 2 && (parts[0] == "approve" || parts[0] == "deny") && len(parts[1]) < 64 {
		v.decision = parts[0]
		v.approval = parts[1]
	}
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
