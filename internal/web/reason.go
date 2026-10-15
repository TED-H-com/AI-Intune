package web

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
)

// ReasonScript counts code points (the same units as the server). Only audit
// reasons are retained in tab-local storage; credentials are never collected.
const ReasonScript = `document.querySelectorAll('input[name="reason"]:not([type="hidden"]),textarea[name="reason"]').forEach(function(input){input.removeAttribute('maxlength');var counter=document.createElement('small');counter.setAttribute('aria-live','polite');input.after(counter);var key='audit-reason:'+location.pathname+':'+(input.form?input.form.action:'');try{if(!input.value)input.value=sessionStorage.getItem(key)||'';}catch(e){}function update(){var n=Array.from(input.value).length;counter.textContent=n+'/500 · max 500 characters';input.setCustomValidity(n>500?'reason is '+n+' characters; maximum is 500':'');try{sessionStorage.setItem(key,input.value);}catch(e){}}input.addEventListener('input',update);update();});`

func ReasonScriptHash() string {
	sum := sha256.Sum256([]byte(ReasonScript))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func init() { funcs["reasonScript"] = func() template.JS { return template.JS(ReasonScript) } }
