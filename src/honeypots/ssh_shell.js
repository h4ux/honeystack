'use strict';

// Very small fake shell used by the SSH honeypot. It intentionally handles
// only a handful of shells commands so attackers see plausible responses
// while every keystroke and command is logged elsewhere.

function buildEnv(cfg) {
  return {
    hostname: cfg.hostname || 'ubuntu',
    user: cfg.username || 'root',
    home: (cfg.username || 'root') === 'root' ? '/root' : `/home/${cfg.username || 'user'}`,
    cwd: (cfg.username || 'root') === 'root' ? '/root' : `/home/${cfg.username || 'user'}`
  };
}

function prompt(env) {
  const cwdShort = env.cwd === env.home ? '~' : env.cwd;
  const sigil = env.user === 'root' ? '#' : '$';
  return `${env.user}@${env.hostname}:${cwdShort}${sigil} `;
}

const FAKE_FS = {
  '/': ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var'],
  '/root': ['.bash_history', '.bashrc', '.cache', '.profile', '.ssh', 'backup.tar.gz', 'notes.txt'],
  '/home': ['ubuntu'],
  '/home/ubuntu': ['.bash_history', '.bashrc', '.cache', '.ssh', 'Documents', 'Downloads'],
  '/etc': ['apache2', 'apt', 'cron.d', 'crontab', 'group', 'hostname', 'hosts', 'nginx', 'os-release', 'passwd', 'shadow', 'ssh', 'sudoers'],
  '/var': ['backups', 'cache', 'lib', 'log', 'mail', 'run', 'spool', 'tmp', 'www'],
  '/var/log': ['auth.log', 'syslog', 'kern.log', 'dpkg.log', 'apt', 'nginx']
};

const FAKE_FILES = {
  '/etc/passwd': `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
`,
  '/etc/hostname': 'web-prod-01\n',
  '/etc/os-release': `PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
`,
  '/proc/cpuinfo': `processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
cpu MHz\t\t: 2500.000
cache size\t: 36608 KB
`,
  '/proc/meminfo': `MemTotal:        4025980 kB
MemFree:          891232 kB
MemAvailable:    2789112 kB
Buffers:          201432 kB
Cached:          1712880 kB
SwapTotal:             0 kB
SwapFree:              0 kB
`
};

function resolve(env, target) {
  if (!target || target === '~') return env.home;
  if (target.startsWith('~/')) return env.home + target.slice(1);
  if (target.startsWith('/')) return normalize(target);
  return normalize(env.cwd + '/' + target);
}

function normalize(p) {
  const parts = p.split('/').filter(Boolean);
  const stack = [];
  for (const part of parts) {
    if (part === '.') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  return '/' + stack.join('/');
}

function runCommand(rawLine, env) {
  const line = rawLine.trim();
  if (!line) return '';
  const [cmd, ...args] = splitArgs(line);
  const arg0 = args[0];

  switch (cmd) {
    case 'exit':
    case 'logout':
    case 'quit':
      return { exit: true };
    case 'clear':
      return '\x1b[H\x1b[2J';
    case 'whoami':
      return env.user + '\n';
    case 'id':
      return env.user === 'root'
        ? 'uid=0(root) gid=0(root) groups=0(root)\n'
        : `uid=1000(${env.user}) gid=1000(${env.user}) groups=1000(${env.user}),27(sudo)\n`;
    case 'hostname':
      return env.hostname + '\n';
    case 'uname':
      if (args.includes('-a')) return `Linux ${env.hostname} 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n`;
      if (args.includes('-r')) return '5.15.0-105-generic\n';
      return 'Linux\n';
    case 'pwd':
      return env.cwd + '\n';
    case 'cd': {
      const target = resolve(env, arg0 || env.home);
      env.cwd = target;
      return '';
    }
    case 'ls': {
      const target = resolve(env, args.find((a) => !a.startsWith('-')) || env.cwd);
      const entries = FAKE_FS[target];
      if (!entries) return `ls: cannot access '${target}': No such file or directory\n`;
      const showAll = args.some((a) => a.startsWith('-') && a.includes('a'));
      const long = args.some((a) => a.startsWith('-') && a.includes('l'));
      const filtered = entries.filter((e) => showAll || !e.startsWith('.'));
      if (long) {
        return filtered.map((e) => `-rw-r--r-- 1 ${env.user} ${env.user} 4096 Apr 12 09:${(Math.floor(Math.random() * 60)).toString().padStart(2, '0')} ${e}`).join('\n') + '\n';
      }
      return filtered.join('  ') + '\n';
    }
    case 'cat': {
      if (!arg0) return '';
      const target = resolve(env, arg0);
      const content = FAKE_FILES[target];
      if (content) return content;
      return `cat: ${arg0}: No such file or directory\n`;
    }
    case 'echo':
      return args.join(' ') + '\n';
    case 'uptime':
      return ` ${new Date().toTimeString().slice(0, 5)}:${String(new Date().getSeconds()).padStart(2, '0')} up 12 days,  4:37,  1 user,  load average: 0.08, 0.03, 0.01\n`;
    case 'w':
    case 'who':
      return `${env.user}   pts/0    ${new Date().toISOString().slice(0, 10)} ${new Date().toTimeString().slice(0, 5)} (10.0.0.14)\n`;
    case 'df':
      return `Filesystem     1K-blocks     Used Available Use% Mounted on\n/dev/root       82537988 35401244  43782796  45% /\ntmpfs            2012988        0   2012988   0% /dev/shm\ntmpfs             805196     1024    804172   1% /run\n`;
    case 'free':
      return `               total        used        free      shared  buff/cache   available\nMem:         4025980      925024      891232         408     2209724     2789112\nSwap:              0           0           0\n`;
    case 'ps':
      return `  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 4321 pts/0    00:00:00 ps\n`;
    case 'ifconfig':
    case 'ip':
      return `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\n    inet 10.0.0.14/24 brd 10.0.0.255 scope global eth0\n`;
    case 'wget':
    case 'curl':
      return runNetworkFetch(cmd, args);
    case 'sudo':
      return `[sudo] password for ${env.user}: \nSorry, try again.\nsudo: 1 incorrect password attempt\n`;
    case 'apt':
    case 'apt-get':
    case 'yum':
    case 'dnf':
      return `Reading package lists... Done\nBuilding dependency tree... Done\nE: Unable to locate package ${args.slice(1).join(' ') || 'unknown'}\n`;
    case 'systemctl':
      return 'System has not been booted with systemd as init system (PID 1). Can\'t operate.\n';
    case 'crontab':
      return 'no crontab for ' + env.user + '\n';
    case 'history':
      return '';
    case 'export':
    case 'set':
    case 'unset':
    case 'alias':
    case 'unalias':
    case 'umask':
      return '';
    case 'python':
    case 'python3':
    case 'perl':
    case 'ruby':
    case 'php':
      return `${cmd}: command not found\n`;
    case 'help':
      return 'GNU bash, version 5.1.16(1)-release\n';
    default:
      return `${cmd}: command not found\n`;
  }
}

function runNetworkFetch(cmd, args) {
  const url = args.find((a) => a.startsWith('http'));
  if (!url) return `${cmd}: try '${cmd} --help' for more information.\n`;
  if (cmd === 'curl') return '';
  return `--${new Date().toISOString().slice(0, 19).replace('T', ' ')}--  ${url}\nResolving host... failed: Temporary failure in name resolution.\nwget: unable to resolve host address\n`;
}

function splitArgs(line) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

module.exports = { buildEnv, prompt, runCommand };
