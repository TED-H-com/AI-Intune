package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/teddashh/AI-Intune/internal/agentrelay"
	"github.com/teddashh/AI-Intune/internal/model"
)

func (h *hub) sendSignin(machine string, c model.SigninCommand) error {
	if c.Operation == "probe" {
		if !h.agentLinks.HasLink(machine) {
			return http.ErrNotSupported
		}
		return nil
	}
	data, e := json.Marshal(c)
	if e != nil {
		return e
	}
	return h.agentLinks.SendMachine(machine, agentrelay.Downstream{Type: agentrelay.DownstreamSignin, Session: c.ID, Data: data})
}
func (h *hub) handleSigninUpdate(w http.ResponseWriter, r *http.Request, machine string) {
	w.Header().Set("Cache-Control", "no-store")
	var u model.SigninUpdate
	if !decode(w, r, &u) {
		return
	}
	if e := h.store.UpdateSignin(machine, u); e != nil {
		writeErr(w, 409, "SIGNIN_ENDED", "Sign-in has ended")
		return
	}
	if len(u.Health) > 0 && len(u.Health) <= 16 {
		_ = h.store.RecordSigninHealth(machine, u.Health, time.Now().UTC())
	}
	w.WriteHeader(http.StatusNoContent)
}
