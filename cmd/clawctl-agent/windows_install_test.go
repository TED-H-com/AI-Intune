package main

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestWindowsInstallerRendersEveryTaskPlaceholder(t *testing.T) {
	taskTokens := regexpSet(regexp.MustCompile(`@@[A-Z0-9_]+@@`), readOpsFile(t, "clawctl-agent.task.xml"), 0)
	script := readOpsFile(t, "install-agent-windows.ps1")
	for token := range taskTokens {
		if !strings.Contains(script, ".Replace('"+token+"'") && !strings.Contains(script, `.Replace("`+token+`"`) {
			t.Errorf("佔位符 %s 只在 task XML 裡，安裝程式不會代換它", token)
		}
	}
}

func TestWindowsInstallerWaitsForAgentAndChecksExitCode(t *testing.T) {
	// PowerShell 5.1 only waits for the GUI-subsystem agent and sets LASTEXITCODE when its output is piped.
	lines := strings.Split(readOpsFile(t, "install-agent-windows.ps1"), "\n")
	invocation := regexp.MustCompile(`&\s+\$(BinSrc|BinFile)\b`)
	pipeline := regexp.MustCompile(`\|\s*Out-(String|Host)\b`)
	exitCheck := regexp.MustCompile(`^\s*if \(\$LASTEXITCODE -ne 0\) \{ Fail "[^"]+" \}\s*$`)
	calls := 0
	for i, line := range lines {
		if !invocation.MatchString(line) {
			continue
		}
		calls++
		if !pipeline.MatchString(line) {
			t.Errorf("line %d: agent invocation must pipe output to Out-String or Out-Host", i+1)
		}
		if i+1 >= len(lines) || !exitCheck.MatchString(lines[i+1]) {
			t.Errorf("line %d: agent invocation must immediately check LASTEXITCODE and fail on non-zero", i+1)
		}
	}
	if calls == 0 {
		t.Fatal("no agent invocations found")
	}
}

func TestWindowsScheduledTaskNameIsTheOneTheInstallerControls(t *testing.T) {
	task := readOpsFile(t, "clawctl-agent.task.xml")
	script := readOpsFile(t, "install-agent-windows.ps1")
	uri := regexp.MustCompile(`<URI>\\clawctl\\([^<]+)</URI>`).FindStringSubmatch(task)
	name := regexp.MustCompile(`(?m)^\$TaskName = '([^']+)'`).FindStringSubmatch(script)
	path := regexp.MustCompile(`(?m)^\$TaskPath = '([^']+)'`).FindStringSubmatch(script)
	if uri == nil || name == nil || path == nil {
		t.Fatal("無法同時讀出 task URI、腳本 TaskName 與 TaskPath")
	}
	if uri[1] != name[1] || path[1] != `\clawctl\` {
		t.Errorf("task URI=%q、腳本 TaskName=%q TaskPath=%q 對不上", uri[1], name[1], path[1])
	}
}

func TestWindowsInstallerDefaultBinarySourceMatchesMakefileOutput(t *testing.T) {
	makefileBytes, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("讀取 Makefile 失敗：%v", err)
	}
	makefile := string(makefileBytes)
	start := strings.Index(makefile, "cross-windows:")
	if start < 0 {
		t.Fatal("Makefile 找不到 cross-windows")
	}
	section := makefile[start:]
	if end := strings.Index(section, "\n\n"); end >= 0 {
		section = section[:end]
	}
	outputs := regexpSet(regexp.MustCompile(`-o\s+build/clawctl-agent-windows-([A-Za-z0-9_]+)`), section, 1)
	script := readOpsFile(t, "install-agent-windows.ps1")
	for arch := range outputs {
		if !strings.Contains(script, "clawctl-agent-windows-"+arch) &&
			!strings.Contains(script, `windows-$AgentArch`) {
			t.Errorf("Makefile 會產生 windows-%s，但安裝程式沒有對應候選", arch)
		}
	}
	if !strings.Contains(script, "clawctl-agent-windows-$AgentArch") {
		t.Error("安裝程式預設候選沒有 clawctl-agent-windows-$AgentArch")
	}
}

func TestWindowsScheduledTaskIsWellFormedXML(t *testing.T) {
	decoder := xml.NewDecoder(strings.NewReader(readOpsFile(t, "clawctl-agent.task.xml")))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("task XML 壞掉：%v", err)
		}
	}
}

func TestWindowsInstallerNormalizesTaskStringEncodingBeforeRegistration(t *testing.T) {
	script := readOpsFile(t, "install-agent-windows.ps1")
	read := strings.Index(script, "$TaskXml = [IO.File]::ReadAllText($TaskTemplate)")
	normalize := strings.Index(script, `$TaskXml = $TaskXml -replace '^<\?xml[^?]*\?>', '<?xml version="1.0" encoding="UTF-16"?>'`)
	register := strings.Index(script, "\n  Register-ScheduledTask ")
	if read < 0 || normalize <= read || register <= normalize {
		t.Fatal("installer must normalize the in-memory XML declaration to UTF-16 before registration")
	}
	if !strings.HasPrefix(readOpsFile(t, "clawctl-agent.task.xml"), `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Fatal("checked-in task template must retain its UTF-8 declaration")
	}
	if !strings.Contains(script, "Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue") {
		t.Fatal("unregistration must remain best-effort")
	}
	if !strings.Contains(script, "-Xml $TaskXml -Force -ErrorAction Stop") ||
		!strings.Contains(script, "} catch {\n  Fail \"Scheduled task registration failed: $($_.Exception.Message)\"") {
		t.Fatal("registration failures must report the exception message")
	}
}

func TestWindowsScheduledTaskStartsDaemonAndInstallerRequiresStoredPlatformEvidence(t *testing.T) {
	task := readOpsFile(t, "clawctl-agent.task.xml")
	if !strings.Contains(task, "<LogonTrigger>") || !strings.Contains(task, "InteractiveToken") ||
		!strings.Contains(task, "LeastPrivilege") {
		t.Fatal("task XML 不是目前使用者的 logon task")
	}
	if strings.Contains(task, "LocalSystem") || strings.Contains(task, "S-1-5-18") {
		t.Fatal("task XML 指定了 LocalSystem")
	}
	if got := dispatch(nil); got != actAgent {
		t.Fatalf("零參數啟動會 dispatch 到 %q，不是 agent check-in loop", got)
	}
	installer := readOpsFile(t, "install-agent-windows.ps1")
	if !strings.Contains(installer, "verify --hub $Hub --since $ServiceStartedAt --timeout 2m --require-platform-evidence") {
		t.Fatal("Windows installer 沒有要求本次 scheduled task 啟動後的 Hub-stored OS/arch evidence")
	}
	if !strings.Contains(installer, "Register-ScheduledTask") {
		t.Fatal("Windows installer 沒有註冊 scheduled task")
	}
}

func TestLinuxInstallerNamesAWindowsInstallerThatExists(t *testing.T) {
	linuxInstaller := readOpsFile(t, "install-agent.sh")
	const windowsPath = "ops/install-agent-windows.ps1"
	if !strings.Contains(linuxInstaller, windowsPath) {
		t.Fatalf("Linux 安裝腳本沒有指出 %s", windowsPath)
	}
	info, err := os.Stat(filepath.Join("..", "..", windowsPath))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("Linux 安裝腳本指出的 %s 不是存在的一般檔", windowsPath)
	}
}

func TestWindowsScheduledTaskHiddenDirectExec(t *testing.T) {
	task := readOpsFile(t, "clawctl-agent.task.xml")
	var parsed struct {
		Settings struct{ Hidden bool }
		Actions  struct {
			Exec struct {
				Command   string
				Arguments string
			}
		}
	}
	if err := xml.Unmarshal([]byte(task), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Settings.Hidden {
		t.Fatal("scheduled task must be hidden")
	}
	if parsed.Actions.Exec.Command != "@@CLAWCTL_AGENT_BIN@@" || parsed.Actions.Exec.Arguments != "" || strings.Contains(strings.ToLower(task), "cmd.exe") {
		t.Fatal("scheduled task must launch agent directly without a wrapper")
	}
}

func TestWindowsTaskBindsInstallingUserAndDelaysLogon(t *testing.T) {
	task := readOpsFile(t, "clawctl-agent.task.xml")
	if strings.Count(task, "<UserId>@@CLAWCTL_AGENT_USER_SID@@</UserId>") != 2 ||
		!strings.Contains(task, "<Delay>PT30S</Delay>") {
		t.Fatal("logon trigger and principal must bind the installing user with a startup delay")
	}
	installer := readOpsFile(t, "install-agent-windows.ps1")
	if !strings.Contains(installer, "(XmlEscape $identity.User.Value)") {
		t.Fatal("installer must use its current user SID")
	}
	if strings.Index(installer, "Set-AgentConfig $ConfigFile $JobsEnabled $Proxy") > strings.Index(installer, "Start-ScheduledTask") {
		t.Fatal("proxy config must be persisted before task startup")
	}
}
