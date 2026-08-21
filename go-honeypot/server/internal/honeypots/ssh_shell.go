package honeypots

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// A very small fake shell that returns plausible responses for common
// commands so that attackers stay engaged while every keystroke is
// logged elsewhere. Nothing is ever executed on the host.

type shellEnv struct {
	hostname string
	user     string
	home     string
	cwd      string
}

func newShellEnv(hostname, user string) *shellEnv {
	if hostname == "" {
		hostname = "ubuntu"
	}
	if user == "" {
		user = "root"
	}
	home := "/home/" + user
	if user == "root" {
		home = "/root"
	}
	return &shellEnv{hostname: hostname, user: user, home: home, cwd: home}
}

func (e *shellEnv) prompt() string {
	sigil := "$"
	if e.user == "root" {
		sigil = "#"
	}
	cwd := e.cwd
	if cwd == e.home {
		cwd = "~"
	}
	return fmt.Sprintf("%s@%s:%s%s ", e.user, e.hostname, cwd, sigil)
}

var fakeFS = map[string][]string{
	"/":            {"bin", "boot", "dev", "etc", "home", "lib", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"},
	"/root":        {".bash_history", ".bashrc", ".cache", ".profile", ".ssh", "backup.tar.gz", "notes.txt"},
	"/home":        {"ubuntu"},
	"/home/ubuntu": {".bash_history", ".bashrc", ".cache", ".ssh", "Documents", "Downloads"},
	"/etc":         {"apache2", "apt", "cron.d", "crontab", "group", "hostname", "hosts", "nginx", "os-release", "passwd", "shadow", "ssh", "sudoers"},
	"/var":         {"backups", "cache", "lib", "log", "mail", "run", "spool", "tmp", "www"},
	"/var/log":     {"auth.log", "syslog", "kern.log", "dpkg.log", "apt", "nginx"},
}

var fakeFiles = map[string]string{
	"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
		"mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false\n" +
		"sshd:x:113:65534::/run/sshd:/usr/sbin/nologin\n" +
		"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
	"/etc/hostname": "web-prod-01\n",
	"/etc/os-release": `PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
`,
	"/proc/cpuinfo": `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
cpu MHz		: 2500.000
cache size	: 36608 KB
`,
	"/proc/meminfo": `MemTotal:        4025980 kB
MemFree:          891232 kB
MemAvailable:    2789112 kB
Buffers:          201432 kB
Cached:          1712880 kB
`,
}

func resolvePath(env *shellEnv, target string) string {
	if target == "" || target == "~" {
		return env.home
	}
	if strings.HasPrefix(target, "~/") {
		return env.home + target[1:]
	}
	if strings.HasPrefix(target, "/") {
		return normalizePath(target)
	}
	return normalizePath(env.cwd + "/" + target)
}

func normalizePath(p string) string {
	parts := strings.Split(p, "/")
	stack := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, part)
		}
	}
	return "/" + strings.Join(stack, "/")
}

type cmdResult struct {
	output string
	exit   bool
}

func runShellCommand(rawLine string, env *shellEnv) cmdResult {
	line := strings.TrimSpace(rawLine)
	if line == "" {
		return cmdResult{}
	}
	tokens := splitCommandLine(line)
	if len(tokens) == 0 {
		return cmdResult{}
	}
	cmd := tokens[0]
	args := tokens[1:]

	firstArg := ""
	if len(args) > 0 {
		firstArg = args[0]
	}

	switch cmd {
	case "exit", "logout", "quit":
		return cmdResult{exit: true}
	case "clear":
		return cmdResult{output: "\x1b[H\x1b[2J"}
	case "whoami":
		return cmdResult{output: env.user + "\n"}
	case "id":
		if env.user == "root" {
			return cmdResult{output: "uid=0(root) gid=0(root) groups=0(root)\n"}
		}
		return cmdResult{output: fmt.Sprintf("uid=1000(%s) gid=1000(%s) groups=1000(%s),27(sudo)\n", env.user, env.user, env.user)}
	case "hostname":
		return cmdResult{output: env.hostname + "\n"}
	case "uname":
		for _, a := range args {
			if a == "-a" {
				return cmdResult{output: fmt.Sprintf("Linux %s 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n", env.hostname)}
			}
			if a == "-r" {
				return cmdResult{output: "5.15.0-105-generic\n"}
			}
		}
		return cmdResult{output: "Linux\n"}
	case "pwd":
		return cmdResult{output: env.cwd + "\n"}
	case "cd":
		env.cwd = resolvePath(env, firstArg)
		return cmdResult{}
	case "ls":
		target := env.cwd
		showAll := false
		long := false
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				if strings.Contains(a, "a") {
					showAll = true
				}
				if strings.Contains(a, "l") {
					long = true
				}
				continue
			}
			target = resolvePath(env, a)
		}
		entries, ok := fakeFS[target]
		if !ok {
			return cmdResult{output: fmt.Sprintf("ls: cannot access '%s': No such file or directory\n", target)}
		}
		filtered := entries[:0:0]
		for _, e := range entries {
			if !showAll && strings.HasPrefix(e, ".") {
				continue
			}
			filtered = append(filtered, e)
		}
		if long {
			var b strings.Builder
			for _, e := range filtered {
				b.WriteString(fmt.Sprintf("-rw-r--r-- 1 %s %s 4096 Apr 12 09:%02d %s\n", env.user, env.user, rand.Intn(60), e))
			}
			return cmdResult{output: b.String()}
		}
		return cmdResult{output: strings.Join(filtered, "  ") + "\n"}
	case "cat":
		if firstArg == "" {
			return cmdResult{}
		}
		target := resolvePath(env, firstArg)
		if s, ok := fakeFiles[target]; ok {
			return cmdResult{output: s}
		}
		return cmdResult{output: fmt.Sprintf("cat: %s: No such file or directory\n", firstArg)}
	case "echo":
		return cmdResult{output: strings.Join(args, " ") + "\n"}
	case "uptime":
		now := time.Now()
		return cmdResult{output: fmt.Sprintf(" %02d:%02d up 12 days,  4:37,  1 user,  load average: 0.08, 0.03, 0.01\n", now.Hour(), now.Minute())}
	case "w", "who":
		return cmdResult{output: fmt.Sprintf("%s   pts/0    %s (10.0.0.14)\n", env.user, time.Now().Format("2006-01-02 15:04"))}
	case "df":
		return cmdResult{output: "Filesystem     1K-blocks     Used Available Use% Mounted on\n/dev/root       82537988 35401244  43782796  45% /\ntmpfs            2012988        0   2012988   0% /dev/shm\n"}
	case "free":
		return cmdResult{output: "               total        used        free      shared  buff/cache   available\nMem:         4025980      925024      891232         408     2209724     2789112\nSwap:              0           0           0\n"}
	case "ps":
		return cmdResult{output: "  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 4321 pts/0    00:00:00 ps\n"}
	case "ifconfig", "ip":
		return cmdResult{output: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\n    inet 10.0.0.14/24 brd 10.0.0.255 scope global eth0\n"}
	case "wget":
		return cmdResult{output: fakeWget(args)}
	case "curl":
		return cmdResult{}
	case "sudo":
		return cmdResult{output: fmt.Sprintf("[sudo] password for %s: \nSorry, try again.\nsudo: 1 incorrect password attempt\n", env.user)}
	case "apt", "apt-get", "yum", "dnf":
		pkg := "unknown"
		if len(args) > 1 {
			pkg = strings.Join(args[1:], " ")
		}
		return cmdResult{output: "Reading package lists... Done\nBuilding dependency tree... Done\nE: Unable to locate package " + pkg + "\n"}
	case "systemctl":
		return cmdResult{output: "System has not been booted with systemd as init system (PID 1). Can't operate.\n"}
	case "crontab":
		return cmdResult{output: "no crontab for " + env.user + "\n"}
	case "history", "export", "set", "unset", "alias", "unalias", "umask":
		return cmdResult{}
	case "python", "python3", "perl", "ruby", "php":
		return cmdResult{output: cmd + ": command not found\n"}
	case "help":
		return cmdResult{output: "GNU bash, version 5.1.16(1)-release\n"}
	default:
		return cmdResult{output: cmd + ": command not found\n"}
	}
}

func fakeWget(args []string) string {
	var url string
	for _, a := range args {
		if strings.HasPrefix(a, "http") {
			url = a
			break
		}
	}
	if url == "" {
		return "wget: missing URL\n"
	}
	return fmt.Sprintf("--%s--  %s\nResolving host... failed: Temporary failure in name resolution.\nwget: unable to resolve host address\n",
		time.Now().UTC().Format("2006-01-02 15:04:05"), url)
}

func splitCommandLine(line string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	for _, r := range line {
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
			continue
		}
		switch r {
		case '"', '\'':
			quote = r
		case ' ', '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
