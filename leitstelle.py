#!/usr/bin/env python3

# TODO
"""
needs config.json (root owned)
creates leitstelle.log and cache.json
"""

import os
import sys
import logging
import json
import subprocess
import argparse

import time
from datetime import datetime, timedelta

import ssl
from urllib.request import socket

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def get_bash(bash_command):
    """Return stdout of given bash command."""
    result = subprocess.run(['bash', '-c', bash_command],
                            stdout=subprocess.PIPE,
                            text=True)
    # check=True, capture_output=True
    return result.stdout.strip("\n")


def send(msg, subject):
    """
    Extend Message Object with sender information and date and sent.
    Extend subject with hostname.

    :param msg: Message object with body
    :returns: None, just sends the Mail
    :raises Exception: I don't raise exceptions
    """

    msg["From"] = cred["from"]
    msg["To"] = cred["to"]
    msg["Date"] = time.ctime(time.time())
    msg["Subject"] = f"[{config['hostname'].upper()}] " + subject

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(cred["domain"], cred["port"],
                              context=context) as server:
            server.login(cred["username"], cred["password"])
            server.sendmail(cred["from"], cred["to"], msg.as_string())
    except smtplib.SMTPException as e:
        logger.error('SMTP error occurred: ' + repr(e))
    except Exception as e:
        logger.error("in send: " + repr(e))


def login_log_since_last():
    """
    SSH logins since last call.
    :returns: log since last run as string
    """
    current_time = datetime.now()
    timefmt = "%Y-%m-%d %H:%M:%S"
    if os.path.exists(config["cachefile"]):
        with open(config["cachefile"]) as handle:
            cache = json.load(handle)
        last_log_send = datetime.strptime(cache["last_log_send"], timefmt)
        cache["last_log_send"] = current_time.strftime(timefmt)
        with open(config["cachefile"], "w") as handle:
            json.dump(cache, handle)

        log = get_bash(f"journalctl -u sshd --since '{last_log_send}'")
        attach = "\n\n" + log
        logger.debug("Attached login log since last send")
    else:  # create cache
        cache = dict()
        cache["last_log_send"] = current_time.strftime(timefmt)
        with open(config["cachefile"], "w") as handle:
            json.dump(cache, handle)
        attach = ""
    return attach


def check_ssl(domain, port='443'):
    """
    :param domain: some site without http/https in the path
    """
    # Alert if not_after is more less 2 Weeks away
    # catch url not reachable for separate notification
    context = ssl.create_default_context()
    with socket.create_connection((domain, port)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            # print(ssock.version())
            date = ssock.getpeercert()

    date = date["notAfter"][:-4]
    expiration = datetime.strptime(date, "%b %d %H:%M:%S %Y")
    delta = expiration - datetime.now()
    if delta < timedelta(weeks=2):
        return (f"SSL certificate for {domain} expires in "
                f"{str(delta).split('.', 2)[0]} on {expiration:%b %d}")
    return None


def check_updates():
    """ return number of available updates. """
    bash_command = ["checkupdates"]
    result = get_bash(bash_command)
    n = len(result.split("\n")) - 1
    return f"{n} updates available"


def run_module(module, **args):
    """
    Run a given function with given arguments and log failures.
    Must return same as module or none
    """
    try:
        return module(**args)
    except Exception as e:
        error = f'Error in module {module.__name__}: {repr(e)}'
        logger.error(error)
        return None


def sshd_log_analysis():
    """
    Plot a histogram of ssh logins
    :returns: attachment as MIMEBase
    """

    import re
    import io
    from email.encoders import encode_base64
    from email.mime.base import MIMEBase
    import numpy as np
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates

    otherformats = [re.compile(x, re.IGNORECASE) for x in [
        r"Accepted publickey for (?P<user>[^\s]+) from (?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d{1,5})",
        r"Failed password for (?P<user>[^\s]+) from (?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d{1,5})",
        r"User (?P<user>[^\s]+) from (?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) not allowed because not listed in AllowUsers"]]

    # with open("log.log") as h:
    #     lines = h.readlines()
    # TODO only last months
    lines = get_bash("journalctl -u sshd -o json").split("\n")

    mydata = {}
    for line in lines:
        datadict = json.loads(line)
        # match the entry
        for i, otherformat in enumerate(otherformats):
            data = re.search(otherformat, datadict["MESSAGE"])
            if data:
                datadict2 = data.groupdict()
                user = datadict2["user"]
                if user not in mydata.keys():
                    mydata[user] = {"acc": {"dt": [], "ip": []},
                                    "rej": {"dt": [], "ip": []}}
                stat = "acc" if i in [0] else "rej"
                mydata[user][stat]["dt"].append(datetime.strptime(
                    datadict["SYSLOG_TIMESTAMP"],
                    "%b %d %H:%M:%S "))
                mydata[user][stat]["ip"].append(datadict2["ipaddress"])
                break

    colors = plt.rcParams['axes.prop_cycle'].by_key()['color']
    users = mydata.keys()
    all_dts = []
    for i, stat in enumerate(["acc", "rej"]):
        all_dts.append([])
        for _, items in mydata.items():
            all_dts[i].append(np.array(items[stat]["dt"]))
    a_all_dts = np.concatenate(all_dts[0] + all_dts[1])
    binwidth = 24  # hours
    bins = np.arange(a_all_dts.min(),
                     a_all_dts.max() + timedelta(hours=binwidth),
                     timedelta(hours=binwidth))

    fig, ax = plt.subplots(2, 1, sharex=True)
    for i, stat in enumerate(["acc", "rej"]):
        ax[i].hist(all_dts[i], bins, histtype='bar', label=list(users),
                   color=colors[:len(users)])
    _ = [ax[i].set_ylim(None, max([ax[i].get_ylim()[1] for i in range(2)]))
         for i in range(2)]
    ax[1].invert_yaxis()
    ax[0].legend()
    fig.autofmt_xdate()
    ax[1].xaxis.set_major_formatter(mdates.DateFormatter('%m-%d'))
    ax[1].xaxis.set_minor_locator(mdates.DayLocator())
    ax[0].set_ylabel("success")
    ax[1].set_ylabel("fail")
    fig.tight_layout()
    plt.subplots_adjust(hspace=0)
    # plt.savefig("hist.png")

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)

    part = MIMEBase('application', "octet-stream")
    part.set_payload(buf.read())
    encode_base64(part)
    part.add_header('Content-Disposition',
                    'attachment; filename="{}"'.format('plot.png'))
    return part


if __name__ == "__main__":

    config = {
        "basedir": f"{os.path.dirname(os.path.realpath(__file__))}",
        "hostname": get_bash('echo "$HOSTNAME"'),  # can be overwritten with config
        "myname": "leitstelle",
    }
    config["logfile"] = f"{config['basedir']}/{config['myname']}.log"
    config["cachefile"] = f"{config['basedir']}/cache.json"
    config["configfile"] = f"{config['basedir']}/config.json"

    # load external config and merge, with ext overwriting internals
    with open(config["configfile"]) as handle:
        extconfig = json.load(handle)
    config = {**config, **extconfig}
    cred = config["cred"]

    parser = argparse.ArgumentParser(description='Leitstelle')
    sp = parser.add_subparsers()
    sp_login = sp.add_parser('login', help='Run this from sshrc with arguments user and IP to inform about logins.')
    sp_login.set_defaults(which='login')
    sp_login.add_argument("user", help="User that logged in.")
    sp_login.add_argument("ip", help="IP of ssh login.")
    sp_boot = sp.add_parser('boot', help='Run with this option on boot to inform about reboots.')
    sp_boot.set_defaults(which='boot')
    sp_periodic = sp.add_parser('periodic', help='Run stuff that is intended to be run periodically (e.g. from CRON).')
    sp_periodic.set_defaults(which='periodic')
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    logging.basicConfig(
        filename=config["logfile"],
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger(__file__)

    # run_module(check_updates)
    if args.which == "periodic":
        logger.info("Running periodic checks")

        msg_text = "\n".join(config["periodic-message"])

        x = run_module(check_ssl, domain=config["sslcheck"])
        if x:
            logger.info(x)
            msg_text += "\n\n" + x

        msg = MIMEMultipart()  # TODO need multipart here for plain text only?
        msg.attach(MIMEText(msg_text, 'plain'))

        # attach hist of logins
        part = run_module(sshd_log_analysis)
        if part:
            msg.attach(part)
        else:
            logger.error("attaching image failed")

        send(msg, "Alive")

    elif args.which == "boot":
        msg = MIMEText(f"{config['hostname']} just rebooted")
        logger.info(f"{config['hostname']} just rebooted")
        send(msg, "Reboot")

    elif args.which == "login":
        loginbyuser = args.user
        loginbyip = args.ip
        attach = login_log_since_last()

        msg = MIMEText(f"Login on {config['hostname']} by user {loginbyuser}.{attach}")
        logger.info(f"Login from {loginbyip} as {loginbyuser}")
        send(msg, f"Login from {loginbyip} as {loginbyuser}")
