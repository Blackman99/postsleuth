#!/usr/bin/env python3
"""Generate the demo/test fixtures (queue.json, mail.log) relative to NOW.

Usage: gen.py [unix_now]   (default: 2026-10-12T07:00:00+08:00)
The tests use the default; the demo GIF uses the current time.
"""
import json, random, sys, datetime as dt

now = int(sys.argv[1]) if len(sys.argv) > 1 else 1791759600
out = sys.argv[2] if len(sys.argv) > 2 else "testdata"
rnd = random.Random(7)
tz = dt.timezone(dt.timedelta(hours=8))
IDCH = "0123456789ABCDEF"

def qid():
    return "".join(rnd.choice(IDCH) for _ in range(10))

GMAIL = "host gmail-smtp-in.l.google.com[142.250.102.27] said: 421-4.7.28 Gmail has detected an unusual rate of unsolicited mail originating from your IP address. To protect our users from spam, mail sent from your IP address has been temporarily rate limited. (in reply to end of DATA command)"
OUTLOOK = "host outlook-com.olc.protection.outlook.com[52.101.42.3] said: 550 5.7.1 Unfortunately, messages from [203.0.113.7] weren't sent. Please contact your Internet service provider since part of their network is on our block list (S3150). (in reply to MAIL FROM command)"
TIMEOUT = "connect to mx.oldcorp.example[198.51.100.20]:25: Connection timed out"
DNS = "Host or domain name not found. Name service error for name=acme-typo.example type=MX: Host not found, try again"
GREY = "host mx1.smallbiz.example[192.0.2.44] said: 450 4.7.1 <ops@smallbiz.example>: Recipient address rejected: Greylisted, see http://postgrey.schweikert.ch/help/smallbiz.example.html (in reply to RCPT TO command)"

senders = ["noreply@example.com", "billing@example.com", "alerts@example.com"]
msgs = []
def add(domain, reason, n, age_min, age_max, local=None):
    for _ in range(n):
        age = rnd.randint(age_min, age_max) * 60
        user = local or rnd.choice(["ana", "li.wei", "j.smith", "kim", "mo", "sara", "tom", "yuki"])
        msgs.append({"queue_name": "deferred", "queue_id": qid(), "arrival_time": now - age,
                     "message_size": rnd.randint(2000, 90000), "forced_expire": False,
                     "sender": rnd.choice(senders),
                     "recipients": [{"address": f"{user}{rnd.randint(1,999)}@{domain}", "delay_reason": reason}]})
add("gmail.com", GMAIL.replace("142.250.102.27", rnd.choice(["142.250.102.27", "142.250.153.26"])), 141, 3, 300)
add("googlemail.com", GMAIL, 9, 10, 200)
add("outlook.com", OUTLOOK, 23, 30, 2000)
add("hotmail.com", OUTLOOK, 11, 60, 1500)
add("oldcorp.example", TIMEOUT, 14, 200, 3000)
add("acme-typo.example", DNS, 4, 600, 2500)
add("smallbiz.example", GREY, 3, 1, 15, local="ops")
for _ in range(6):
    msgs.append({"queue_name": "active", "queue_id": qid(), "arrival_time": now - rnd.randint(0, 90),
                 "message_size": 4100, "forced_expire": False, "sender": "noreply@example.com",
                 "recipients": [{"address": f"u{rnd.randint(1,99)}@fastmail.com"}]})
msgs.append({"queue_name": "hold", "queue_id": qid(), "arrival_time": now - 7200, "message_size": 812000,
             "forced_expire": False, "sender": "marketing@example.com",
             "recipients": [{"address": "list@lists.example.org"}]})
rnd.shuffle(msgs)
with open(f"{out}/queue.json", "w") as f:
    for m in msgs:
        f.write(json.dumps(m) + "\n")

# mail log over the last 24h, traditional syslog timestamps
lines = []
def ts(t):
    return dt.datetime.fromtimestamp(t, tz).strftime("%b %e %H:%M:%S")
def deliver(t, to, status, detail, relay="none", dsn="2.0.0"):
    q = qid()
    lines.append((t, f"{ts(t)} mail postfix/smtpd[{rnd.randint(1000,9999)}]: {q}: client=app1.internal[10.0.0.5]"))
    lines.append((t, f"{ts(t)} mail postfix/cleanup[{rnd.randint(1000,9999)}]: {q}: message-id=<{qid().lower()}@example.com>"))
    lines.append((t + 1, f"{ts(t+1)} mail opendkim[812]: {q}: DKIM-Signature field added (s=mail, d=example.com)"))
    lines.append((t + 1, f"{ts(t+1)} mail postfix/qmgr[1201]: {q}: from=<noreply@example.com>, size=5120, nrcpt=1 (queue active)"))
    lines.append((t + 2, f"{ts(t+2)} mail postfix/smtp[{rnd.randint(1000,9999)}]: {q}: to=<{to}>, relay={relay}, delay=1.2, delays=0.1/0/0.6/0.5, dsn={dsn}, status={status} ({detail})"))
    if status in ("sent", "bounced"):
        if status == "bounced":
            b = qid()
            lines.append((t + 2, f"{ts(t+2)} mail postfix/bounce[3301]: {q}: sender non-delivery notification: {b}"))
            lines.append((t + 2, f"{ts(t+2)} mail postfix/qmgr[1201]: {b}: from=<>, size=7200, nrcpt=1 (queue active)"))
            lines.append((t + 3, f"{ts(t+3)} mail postfix/local[4410]: {b}: to=<noreply@example.com>, relay=local, delay=0.1, delays=0/0/0/0.1, dsn=2.0.0, status=sent (delivered to mailbox)"))
            lines.append((t + 3, f"{ts(t+3)} mail postfix/qmgr[1201]: {b}: removed"))
        lines.append((t + 3, f"{ts(t+3)} mail postfix/qmgr[1201]: {q}: removed"))
    return q
start = now - 24 * 3600
for i in range(900):
    t = start + rnd.randint(0, 24 * 3600 - 60)
    d = rnd.choice(["gmail.com"] * 5 + ["outlook.com", "yahoo.com", "fastmail.com", "proton.me", "qq.com"])
    if d == "gmail.com" and t > now - 5 * 3600:
        deliver(t, f"user{i}@{d}", "deferred", GMAIL, relay="gmail-smtp-in.l.google.com[142.250.102.27]:25", dsn="4.7.28")
    elif d == "outlook.com" and t > now - 34 * 3600 and rnd.random() < 0.7:
        deliver(t, f"user{i}@{d}", "bounced" if rnd.random() < 0.3 else "deferred", OUTLOOK, relay="outlook-com.olc.protection.outlook.com[52.101.42.3]:25", dsn="5.7.1")
    else:
        deliver(t, f"user{i}@{d}", "sent", f"250 2.0.0 OK  {rnd.randint(10**9, 10**10)} - gsmtp", relay=f"mx.{d}[192.0.2.10]:25")
for i in range(12):
    t = start + rnd.randint(0, 24 * 3600)
    deliver(t, f"old.user{i}@yahoo.com", "bounced", "host mta7.am0.yahoodns.net[67.195.204.72] said: 554 5.1.1 <old.user@yahoo.com>: Recipient address rejected: User unknown (in reply to RCPT TO command)", relay="mta7.am0.yahoodns.net[67.195.204.72]:25", dsn="5.1.1")
for i in range(5):
    t = start + rnd.randint(0, 24 * 3600)
    deliver(t, f"ceo@oldcorp.example", "deferred", TIMEOUT, dsn="4.4.1")
for i in range(30):
    t = start + rnd.randint(0, 24 * 3600)
    ip = f"185.220.{rnd.randint(1,250)}.{rnd.randint(1,250)}"
    lines.append((t, f"{ts(t)} mail postfix/smtpd[{rnd.randint(1000,9999)}]: NOQUEUE: reject: RCPT from unknown[{ip}]: 554 5.7.1 <x{i}@gmail.com>: Relay access denied; from=<spam@bad.example> to=<x{i}@gmail.com> proto=ESMTP helo=<WIN-{qid()}>"))
t = now - 600
lines.append((t, f"{ts(t)} mail postfix/qmgr[1201]: 7A1B2C3D4E: from=<alerts@example.com>, status=expired, returned to sender"))
lines.append((t, f"{ts(t)} mail sshd[22]: unrelated line"))
lines.sort(key=lambda x: x[0])
with open(f"{out}/mail.log", "w") as f:
    for _, l in lines:
        f.write(l + "\n")
