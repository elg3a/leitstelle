# Leitstelle
Notifications and logging for server administration tasks.


## Installation
To be run as root to ensure that everything is accessible while at the same
time not allowing access to data (e.g credentials, log) to anyone else.

Allow privileged execution only for everyone (or group) via `visudo`:
```sh
ALL ALL=(ALL) NOPASSWD: /path/to/leitstelle.py
```

Ensure to make the script root owned and executable:
```sh
$ chown root:root leitstelle.py
$ chmod +x leitstelle.py
$ chmod 600 config.json
```

In `/etc/ssh/sshrc` with arguments user and ssh connection ip:
```
user=$USER
ip=$(echo $SSH_CONNECTION | cut -d ' ' -f 1)
sudo /path/to/leitstelle.py login $user $ip
```

Periodic systemd (or with cron: in `sudo crontab -e` do `@reboot yourScriptPath`):

`/etc/systemd/system/leitstelle-periodic.timer`
```
[Unit]
Description=Run leitstelle periodically

[Timer]
OnCalendar=Sat *-*-1..7 12:00:00
Persistent=true

[Install]
WantedBy=timers.target
```
and

`/etc/systemd/system/leitstelle-periodic.service`
```
[Unit]
Description=Run leitstelle periodically with timer
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/home/backup/leitstelle.py periodic

[Install]
WantedBy=multi-user.target
```
```sh
$ systemctl enable leitstelle-periodic.timer
$ systemctl start leitstelle-periodic.timer
$ systemctl list-timers
```

Systemd service on boot:

`/etc/systemd/system/leitstelle.service`
```
[Unit]
Description=Run leitstelle on boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/home/backup/leitstelle.py boot

[Install]
WantedBy=multi-user.target
```
```sh
$ systemctl enable leitstelle
```

Configuration file: Fill in template of `config.json`


## Architecture concepts
- single executable
- flags:
  - --periodic - run with cron/systemd
    - need to update (and list packages or number of if to many)
    - ssh login summary
    - url reachability, ssl cert duration
  - --login - on login (sshrc)
    - notify about user and ip
    - every DELTA provide extended parse of syslog -> needs cache
  - --boot - on startup
    - to notify about reboots


## ToDo
- auto install via option
- unit and integration tests with mock data
- code formating and static code analysis
- monitore systemd-logind instead of sshd?

### Future Extension
- test sshd security (also check for updates of the script)
- automatic nmap port scans
- nginx connection summary
- tor connects -> continuous monitoring?
- number of Borg repos/auto check size of backup repo folder
- extra modes: provide api to log/notify, e.g. if Borg prune fails
- other notification backends, e.g. signal/matrix
