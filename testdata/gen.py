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

# One queued message as `postcat -e -h -q ID` prints it (envelope + primary
# headers, never the body): the oldest deferred Gmail message in the queue.
m = min((m for m in msgs if m["queue_name"] == "deferred" and m["recipients"][0]["address"].endswith("@gmail.com")),
        key=lambda m: m["arrival_time"])
q, at, rcpt = m["queue_id"], m["arrival_time"], m["recipients"][0]["address"]
def rfc(t):
    return dt.datetime.fromtimestamp(t, tz).strftime("%a, %d %b %Y %H:%M:%S +0800 (CST)")
asct = dt.datetime.fromtimestamp(at, tz).strftime("%a %b %e %H:%M:%S %Y")
path = f"deferred/{q[0]}/{q}"
size = m["message_size"]
pc = f"""*** ENVELOPE RECORDS {path} ***
message_size:           {size:>5}             812               2               0           {size:>5}               0
message_arrival_time: {asct}
create_time: {asct}
named_attribute: rewrite_context=remote
sender_fullname: 
sender: alerts@example.com
named_attribute: log_client_name=app01.internal
named_attribute: log_client_address=10.0.0.12
named_attribute: log_message_origin=app01.internal[10.0.0.12]
named_attribute: log_helo_name=app01.internal
named_attribute: log_protocol_name=ESMTP
named_attribute: client_name=app01.internal
named_attribute: reverse_client_name=app01.internal
named_attribute: client_address=10.0.0.12
named_attribute: client_port=40312
named_attribute: server_address=10.0.0.2
named_attribute: server_port=25
named_attribute: helo_name=app01.internal
named_attribute: protocol_name=ESMTPS
named_attribute: client_address_type=2
named_attribute: dsn_orig_rcpt=rfc822;{rcpt}
original_recipient: {rcpt}
recipient: {rcpt}
named_attribute: dsn_orig_rcpt=rfc822;oncall@example.org
original_recipient: oncall@example.org
done_recipient: oncall@example.org
*** MESSAGE CONTENTS {path} ***
Received: from app01.internal (app01.internal [10.0.0.12])
\t(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
\t key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
\t(No client certificate requested)
\tby mail.example.com (Postfix) with ESMTPS id {q};
\t{rfc(at)}
Received: by app01.internal (Postfix, from userid 1001)
\tid 4bNqJx2rG9z1Hk; {rfc(at - 1)}
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;
\ts=mail; t={at}; bh=Zm9vYmFyYmF6cXV4cXV1eGZvb2JhcmJhenF1eHF1dXg=;
\th=From:To:Subject:Date:Message-ID:List-Unsubscribe;
\tb=c2lnbmF0dXJlLXRoYXQtZG9lcy1ub3QtbWF0dGVyLWhlcmUtaXQtaXMtYW5vbnltaXNlZA
\t aGVyZS1pcy1zb21lLW1vcmUtYmFzZTY0LWZvci10aGUtc2lnbmF0dXJl
From: "Example Alerts" <alerts@example.com>
To: Jamie Smith <{rcpt}>, On-call <oncall@example.org>
Subject: [ALERT] db-3 disk usage above 90% for 15 minutes
Date: {rfc(at - 1)}
Message-ID: <{at}.4bNqJx2rG9@app01.example.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="=_b1_9f8e7d6c"
Precedence: bulk
List-Unsubscribe: <mailto:unsubscribe@example.com?subject=unsub-{q.lower()}>
X-Mailer: alertd 4.2.1
X-Api-Key: alertd-demo-key-9f8e7d6c5b4a3928
*** HEADER EXTRACTED {path} ***
named_attribute: encoding=8bit
*** MESSAGE FILE END {path} ***
"""
with open(f"{out}/postcat-{q}.txt", "w") as f:
    f.write(pc)
