# Leitstelle
Notifications and logging for server administration tasks.


# ToDo
- auto install via option
- unit and integration tests with mock data
- code formating and static code analysis


## Installation
To be run as root to ensure that everything is accessible while at the same
time not allowing access to data (e.g credentials, log) to anyone else.

Allow privileged execution only for everyone (or group) via `visudo`:
    `ALL ALL=(ALL) NOPASSWD: /path/to/leitstelle.py`

Ensure to make the script root owned and executable:
    $ chown root:root leitstelle.py
    $ chmod +x leitstelle.py

In `/etc/ssh/sshrc` with arguments user and ssh connection ip:
    ```
    user=$USER
    ip=$(echo $SSH_CONNECTION | cut -d ' ' -f 1)
    sudo /path/to/leitstelle.py login $user $ip
    ```

Weekly systemd (or cron: in sudo crontab -e do @reboot yourScriptPath):
    `/etc/systemd/system/leitstelle-periodic.timer`
    ```
    [Unit]
    Description=Run leitstelle periodically

    [Timer]
    OnCalendar=Sat 12:00
    Persistent=true

    [Install]
    WantedBy=timers.target
    ```
    AND
    `/etc/systemd/system/leitstelle-periodic.service`
    ```
    [Unit]
    Description=Run leitstelle periodically with timer
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=oneshot
    ExecStart=/home/backup/leitstelle.py weekly

    [Install]
    WantedBy=multi-user.target
    ```
    $ systemctl enable leitstelle-periodic.timer
    $ systemctl start leitstelle-periodic.timer
        $ systemctl list-timers

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
    $ systemctl enable leitstelle

Configuration file:
    Fill template of `config.json`


## Architecture concepts
- single executable
- flags:
  --weekly - run with cron/systemd
    - need to update (and list packages or number of if to many)
    - ssh login summary
    - url reachability, ssl cert duration
  --login - on login (sshrc)
    - notify about user and ip
    - every DELTA provide extended parse of syslog -> needs cache
  --boot - on startup
    - to notify about reboots


## EXTENSION
- test sshd security (also check for updates of the script)
- automatic nmap port scans
- nginx connection summary
- tor connects -> continuous monitoring?
- number of Borg repos/auto check size of backup repo folder
- extra modes: provide api to log/notify, e.g. if Borg prune fails
- other notification backends, e.g. signal/matrix
