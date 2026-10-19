package provider

import "regexp"

// Official reference pages. Every URL here was checked to resolve (some land
// on a sign-in page, which is expected for Postmaster Tools, SNDS, JMRP and
// the Outlook.com support form).
var (
	refGmailGuidelines = Ref{"Email sender guidelines", "https://support.google.com/mail/answer/81126"}
	refGmailErrors     = Ref{"Gmail SMTP errors and codes", "https://support.google.com/a/answer/3726730"}
	refGmailFAQ        = Ref{"Email sender guidelines FAQ", "https://support.google.com/a/answer/14229414"}
	refPostmasterTools = Ref{"Postmaster Tools (sign in)", "https://postmaster.google.com/"}
	refPostmasterSetup = Ref{"Set up Postmaster Tools", "https://support.google.com/mail/answer/9981691"}
	refGmailBlocks     = Ref{"How Gmail blocks messages", "https://support.google.com/mail/answer/188131"}
	refGmailTroubles   = Ref{"Troubleshooting for senders", "https://support.google.com/mail/troubleshooter/2696779"}
	refGmailContact    = Ref{"Sender contact form (mitigation)", "https://support.google.com/mail/contact/gmail_bulk_sender_escalation"}

	refMSTroubleshoot = Ref{"Postmaster: troubleshooting, codes", "https://substrate.office.com/ip-domain-management-snds/Postmaster/Troubleshooting"}
	refMSPolicies     = Ref{"Postmaster: policies and guidelines", "https://substrate.office.com/ip-domain-management-snds/Postmaster/Policies"}
	refSNDS           = Ref{"SNDS: IP status and data (sign in)", "https://substrate.office.com/ip-domain-management-snds/SNDS"}
	refJMRP           = Ref{"JMRP: junk reports (in SNDS)", "https://substrate.office.com/ip-domain-management-snds/SNDS/Jmrp"}
	refOLCSupport     = Ref{"Outlook.com sender support form", "https://olcsupport.office.com/"}
	refDelistDoc      = Ref{"Delist portal guide, fix 5.7.511", "https://learn.microsoft.com/en-us/defender-office-365/external-senders-use-the-delist-portal-to-unblock-yourself"}
	refDelistPortal   = Ref{"Anti-Spam IP Delist Portal", "https://sender.office.com/"}
	refEXONDR         = Ref{"Fix NDR 5.7.705, 5.7.708, 5.7.750", "https://learn.microsoft.com/en-us/troubleshoot/exchange/email-delivery/ndr/fix-error-codes-550-5-7-703-550-5-7-705-550-5-7-708-550-5-7-750"}

	refYahooTS      = Ref{"SMTP error codes: TS* deferrals", "https://senders.yahooinc.com/smtp-error-codes/#ts-errors"}
	refYahoo5xx     = Ref{"SMTP error codes: 5xx errors", "https://senders.yahooinc.com/smtp-error-codes/#5xx"}
	refYahooAuth    = Ref{"SMTP error codes: authentication", "https://senders.yahooinc.com/smtp-error-codes/#authentication-failures"}
	refYahooPolicy  = Ref{"SMTP error codes: content, policy", "https://senders.yahooinc.com/smtp-error-codes/#ph-errors"}
	refYahooReqs    = Ref{"Sender requirements", "https://senders.yahooinc.com/best-practices/"}
	refYahooCFL     = Ref{"Complaint Feedback Loop (CFL)", "https://senders.yahooinc.com/complaint-feedback-loop/"}
	refYahooContact = Ref{"Sender support request", "https://senders.yahooinc.com/contact/"}
	refSpamhaus     = Ref{"Spamhaus (IP lookup)", "https://www.spamhaus.org/"}
)

const noFlush = "Don't flush the queue (postqueue -f, postsleuth flush): a burst of retries counts against you."

// Order matters within a provider: the first matching playbook wins.
var playbooks = []Playbook{
	// ---------------------------------------------------------------- Gmail
	{
		ID: "gmail-4.7.28", Provider: Gmail, Codes: "421 4.7.28",
		Title:   "Gmail is rate limiting you: unusual rate of mail",
		Meaning: "Gmail saw an unusual rate of (unsolicited) mail from your IP, IP netblock, DKIM domain, SPF domain or a URL domain in the message, and is temporarily rate limiting it. Postfix keeps the mail deferred and retries.",
		Steps: []string{
			"Send nothing to Gmail for at least 10 minutes. " + noFlush,
			"Read the reply for which quota you hit: IP address, IP Netblock, DKIM domain, SPF domain or URL domain. If it doesn't say, assume IP, DKIM and SPF are all affected.",
			"After 10 minutes, send over one connection: a gmail transport (master.cf: gmail unix - - n - - smtp; transport_maps: gmail.com gmail:) with gmail_destination_concurrency_limit = 1. Google counts per MX host, so Workspace-hosted domains share the limit.",
			"If that connection is accepted, raise the limit one connection at a time. If it is deferred again, wait another 10 minutes.",
			"Find what caused the spike: a bulk send, a new IP that wasn't warmed up, or a compromised account, web form or script. postsleuth queue --list --domain gmail.com shows who is sending.",
			"Check spam rate and IP/domain reputation in Postmaster Tools. Google asks for a spam rate below 0.10% and never 0.30% or higher.",
		},
		Refs: []Ref{refGmailGuidelines, refGmailErrors, refPostmasterTools, refPostmasterSetup},
		re:   regexp.MustCompile(`(?i)\b(4\.7\.28)\b|Gmail has detected an unusual rate of unsolicited`),
	},
	{
		ID: "gmail-auth", Provider: Gmail, Codes: "4.7.26 / 5.7.26, 5.7.27, 5.7.30, 5.7.32, 5.7.40",
		Title:   "Gmail: mail failed SPF, DKIM or DMARC checks",
		Meaning: "Gmail requires every sender to pass SPF or DKIM; senders of 5,000+ messages a day to Gmail need SPF, DKIM and DMARC, with the From: domain aligned to the SPF or DKIM domain. The reply says which check failed. 4.7.x codes are deferrals that retry; 5.7.x codes bounce.",
		Steps: []string{
			"Run postsleuth dns YOUR-DOMAIN --ip YOUR-SENDING-IP: SPF must authorise the IP Postfix sends from, DKIM must sign with a published key (1024 bits minimum, 2048 recommended), and a DMARC record must exist.",
			"Fix the check the reply names: \"DKIM = did not pass\", \"SPF ... = did not pass\", the domain's DMARC policy, or a From: domain that isn't aligned (5.7.32).",
			"Make sure Postfix signs everything: the DKIM milter must be in smtpd_milters and non_smtpd_milters, or mail submitted by local apps through sendmail goes out unsigned.",
			"If this server forwards other people's mail (aliases, lists), their SPF can't pass from your IP: rewrite the envelope sender (SRS) and don't modify signed headers or bodies.",
			"5.7.x bounces are not retried: have them resent once the checks pass. 4.7.x deferrals go out on the next retry.",
		},
		Refs: []Ref{refGmailGuidelines, refGmailErrors, refGmailFAQ},
		CodeNotes: map[string]string{
			"4.7.26": "unauthenticated (neither SPF nor DKIM passed), or DMARC could not be evaluated because of a DNS failure",
			"5.7.26": "unauthenticated, an SPF hard fail, or the From: domain's DMARC policy rejected it",
			"4.7.27": "SPF did not pass", "5.7.27": "SPF did not pass",
			"4.7.30": "DKIM did not pass", "5.7.30": "DKIM did not pass",
			"4.7.32": "From: not aligned with the SPF or DKIM domain", "5.7.32": "From: not aligned with the SPF or DKIM domain",
			"4.7.40": "no DMARC record, or it sets no policy", "5.7.40": "no DMARC record, or it sets no policy",
		},
		re: regexp.MustCompile(`(?i)\b([45]\.7\.(?:26|27|30|32))\b|\b([45]\.7\.40)\b.*\bDMARC\b`),
	},
	{
		ID: "gmail-ptr", Provider: Gmail, Codes: "421 4.7.0, 451 4.7.23, 550 5.7.25, 550 5.7.1 (IPv6)",
		Title:   "Gmail: reverse DNS (PTR) missing or not forward-confirmed",
		Meaning: "Gmail requires the sending IP to have a PTR record whose hostname resolves back to the same IP (forward-confirmed reverse DNS); for IPv6 the IPv6 address needs its own PTR.",
		Steps: []string{
			"Run postsleuth dns --ip YOUR-SENDING-IP to see the PTR and whether it resolves back to the IP.",
			"Ask whoever owns the IP (hosting provider or ISP) to set the PTR to your mail hostname, and give that hostname an A/AAAA record for the same IP, ideally matching myhostname.",
			"If the reply mentions IPv6 and your IPv6 address has no PTR, prefer IPv4 (smtp_address_preference = ipv4) or stop sending over IPv6 (inet_protocols = ipv4) until it does.",
			"Deferrals clear on retry once DNS is fixed (allow for the record's TTL); 5.7.25 bounces must be resent.",
		},
		Refs: []Ref{refGmailGuidelines, refGmailErrors},
		CodeNotes: map[string]string{
			"4.7.23": "no PTR, or the PTR's hostname doesn't resolve back: rate limited",
			"5.7.25": "no PTR, or the PTR's hostname doesn't resolve back: blocked",
		},
		re: regexp.MustCompile(`(?i)\b(4\.7\.23|5\.7\.25)\b|does(?: not|n't) have a PTR record|IPv6 sending guidelines`),
	},
	{
		ID: "gmail-tls", Provider: Gmail, Codes: "421 4.7.29 / 550 5.7.29, 421 4.7.0 (TLS required)",
		Title:   "Gmail: mail must be sent over TLS",
		Meaning: "Gmail rate limits or blocks mail that isn't sent over a TLS connection.",
		Steps: []string{
			"Check smtp_tls_security_level with postsleuth config; set it to may (or stronger) so Postfix uses STARTTLS whenever the receiver offers it.",
			"Make sure no smtp_tls_policy_maps entry forces none for Gmail or Google-hosted domains.",
			"Run postfix reload; deferred mail goes out on the next retry, 5.7.29 bounces must be resent.",
		},
		Refs: []Ref{refGmailGuidelines, refGmailErrors},
		CodeNotes: map[string]string{
			"4.7.29": "not sent over TLS: rate limited",
			"5.7.29": "not sent over TLS: blocked",
		},
		re: regexp.MustCompile(`(?i)\b([45]\.7\.29)\b|TLS required for RCPT domain`),
	},
	{
		ID: "gmail-reputation", Provider: Gmail, Codes: "421 4.7.0, 550 5.7.1, 550 5.7.28",
		Title:   "Gmail: blocked for low reputation or unsolicited mail",
		Meaning: "Gmail's filters refused the mail because of the sending IP's or domain's reputation, or because of the content or links. 4.7.0 replies are deferrals; 5.7.1 and 5.7.28 bounce.",
		Steps: []string{
			"Open Postmaster Tools for your sending domain: spam rate, IP reputation and domain reputation tell you which one Gmail is reacting to.",
			"Make sure this server isn't sending spam: postsleuth queue --list --domain gmail.com shows the senders; look for a compromised account, web form or script.",
			"Send only to people who asked for the mail; drop old, bought and bouncing addresses. Bulk marketing mail needs one-click unsubscribe (List-Unsubscribe and List-Unsubscribe-Post).",
			"If you share an IP (hosting provider, relay service), check it isn't on a public blocklist: the neighbours' reputation is yours too.",
			"Check that the domains linked in your messages aren't flagged by Google Safe Browsing.",
			"If you follow the sender guidelines and are still blocked, use the Gmail sender contact form; mitigation requests are reviewed against fixed criteria.",
		},
		Refs: []Ref{refGmailBlocks, refPostmasterTools, refGmailGuidelines, refGmailTroubles, refGmailContact},
		re:   regexp.MustCompile(`(?i)\b(5\.7\.28)\b|low reputation of the sending|likely unsolicited|suspicious due to the nature of the content|\b(5\.7\.1)\b.*\bunsolicited\b`),
	},
	{
		ID: "gmail-relay-required", Provider: Gmail, Codes: "550 5.7.1",
		Title:   "Gmail: this IP may not send mail directly",
		Meaning: "Gmail won't accept mail directly from this IP address and asks you to send through your service provider's SMTP relay instead.",
		Steps: []string{
			"Send through your provider's or ISP's smarthost: relayhost = [smtp.example.net]:587 with SASL (smtp_sasl_auth_enable = yes, smtp_sasl_password_maps).",
			"Or move outgoing mail to a server with a static IP and a proper PTR record.",
			"These are bounces: resend once mail leaves through the relay.",
		},
		Refs: []Ref{refGmailErrors, refGmailGuidelines},
		re:   regexp.MustCompile(`(?i)not authorized to send email directly`),
	},

	// ------------------------------------------------------------ Microsoft
	{
		ID: "microsoft-s3150", Provider: Microsoft, Codes: "550 5.7.1 (S3150 / S3140)",
		Title:   "Outlook.com block list: your IP's network is blocked",
		Meaning: "Outlook.com (outlook.com, hotmail.com, live.com, msn.com) has put your sending IP, or part of its network, on its own block list. Retrying won't help; mail keeps bouncing until the block is lifted.",
		Steps: []string{
			"Fix the cause first: spam leaving this server (a compromised account, form or script: postsleuth queue --list --domain outlook.com), bad lists, and SPF/DKIM/DMARC/PTR gaps (postsleuth dns).",
			"Sign in to SNDS, request access for your IP range, and check the IP's status and complaint data.",
			"Enrol in JMRP (inside SNDS) to get a copy of every message Outlook.com users mark as junk, and stop mailing those people.",
			"Request delisting with the Outlook.com sender support form: give the IP and the full bounce line. If mail still bounces after the reply, answer it with fresh bounce lines.",
			"sender.office.com is for Microsoft 365 \"banned sending IP\" errors (5.7.606-649), not for S3150.",
		},
		Refs: []Ref{refMSTroubleshoot, refSNDS, refJMRP, refOLCSupport},
		re:   regexp.MustCompile(`(?i)part of their network is on our block list.*?\((S3\d{3})\)|\((S3150|S3140)\)|part of their network is on our block list`),
	},
	{
		ID: "microsoft-banned-ip", Provider: Microsoft, Codes: "550 5.7.606-649",
		Title:   "Microsoft 365: banned sending IP",
		Meaning: "Your IP is on the Microsoft 365 blocked senders list, so organisations whose mail is hosted on Microsoft 365 (Exchange Online) reject it.",
		Steps: []string{
			"Stop the cause first: Microsoft blocks the IP again if it keeps sending spam. Check the queue and log for mail you didn't mean to send.",
			"Open the Anti-Spam IP Delist Portal (sender.office.com), enter the address that received the bounce and the IP from the error (one of each per visit), and submit.",
			"Open the confirmation link Microsoft emails you and select Delist IP. Microsoft says removal can take up to 24 hours or longer.",
			"These are bounces: resend after the IP is delisted.",
		},
		Refs: []Ref{refDelistDoc, refDelistPortal},
		re:   regexp.MustCompile(`(?i)\b(5\.7\.6(?:0[6-9]|[1-4]\d))\b|banned sending ip`),
	},
	{
		ID: "microsoft-5.7.511", Provider: Microsoft, Codes: "550 5.7.511",
		Title:   "Microsoft 365: banned sender (needs a manual review)",
		Meaning: "Microsoft wants to investigate traffic from your IP; the self-service delist portal can't remove this block.",
		Steps: []string{
			"Fix whatever sent the unwanted mail first: postsleuth log shows the volume per domain, and the queue shows the senders.",
			"Forward the full bounce (NDR) with the IP to delist@microsoft.com, as the error says. Microsoft says it answers within 48 hours.",
		},
		Refs: []Ref{refDelistDoc},
		re:   regexp.MustCompile(`(?i)\b(5\.7\.511)\b`),
	},
	{
		ID: "microsoft-rate-limit", Provider: Microsoft, Codes: "451 4.7.650, 421 RP-001 / RP-002 / RP-003",
		Title:   "Outlook.com is rate limiting you because of IP reputation",
		Meaning: "Outlook.com is throttling your IP because of its reputation. Postfix keeps retrying, but a large backlog can reach maximal_queue_lifetime before Microsoft accepts it.",
		Steps: []string{
			noFlush + " Postfix's backoff is what you want here.",
			"Lower the pressure on Microsoft: route outlook.com, hotmail.com, live.com and msn.com through their own transport with a small process limit in master.cf (e.g. outlook unix - - n - 2 smtp) and outlook_destination_rate_delay = 1s.",
			"Check the IP in SNDS: complaint rate, spam-trap hits, and whether it is filtered.",
			"Enrol in JMRP and remove everyone who marks your mail as junk.",
			"If the IP is new, ramp up slowly: Microsoft says a new IP is usually fully ramped within a couple of weeks when complaints stay low.",
			"If it lasts for days, open a request with Outlook.com sender support, with the full reply text and your IPs.",
		},
		Refs: []Ref{refMSTroubleshoot, refSNDS, refJMRP, refOLCSupport},
		CodeNotes: map[string]string{
			"RP-001": "the IP exceeded the allowed message rate (reason: IP/domain reputation)",
			"RP-002": "the IP exceeded the allowed rate on this connection (reason: IP/domain reputation)",
			"RP-003": "the IP exceeded the allowed number of connections (reason: IP/domain reputation)",
		},
		re: regexp.MustCompile(`(?i)\b(4\.7\.65[01])\b|temporarily rate limited due to IP reputation|\b(RP-00[1-3])\b`),
	},
	{
		ID: "microsoft-policy", Provider: Microsoft, Codes: "550 SC-001..004, DY-001/002, OU-001/002",
		Title:   "Outlook.com rejected the mail for policy reasons",
		Meaning: "Outlook.com rejected the connection or message for a policy reason; the code says which (see code notes).",
		Steps: []string{
			"SC-003 or DY-002: treat it as a compromise until proven otherwise. Make sure Postfix is not an open relay (smtpd_relay_restrictions) and look for unexpected senders in the queue.",
			"DY-001: this IP looks dynamic; send through a smarthost (relayhost) or move to a static IP with a proper PTR.",
			"OU-001: look the IP up at Spamhaus and fix the listing there.",
			"SC-001, SC-004 or OU-002: reputation and complaints. Check the IP in SNDS, enrol in JMRP, and clean your lists.",
			"SC-002: stop probing Outlook.com for valid addresses (list-cleaning tools, or Postfix reject_unverified_sender/recipient probes towards Outlook.com).",
			"Once the cause is fixed, ask Outlook.com sender support to review the IP.",
		},
		Refs: []Ref{refMSTroubleshoot, refSNDS, refJMRP, refOLCSupport},
		CodeNotes: map[string]string{
			"SC-001": "content with spam-like characteristics or IP/domain reputation",
			"SC-002": "the IP showed namespace mining (checking addresses without sending)",
			"SC-003": "the IP appears to be an open proxy or relay",
			"SC-004": "blocked because of complaints about mail from the IP; Microsoft recommends JMRP",
			"DY-001": "Outlook.com generally doesn't accept mail from dynamic IPs",
			"DY-002": "likely a compromised or virus-infected server or computer",
			"OU-001": "Microsoft refers to Spamhaus for this block and its removal",
			"OU-002": "content with spam-like characteristics or IP/domain reputation",
		},
		re: regexp.MustCompile(`(?i)\b(SC-00[1-4]|DY-00[12]|OU-00[12])\b`),
	},
	{
		ID: "microsoft-5.7.515", Provider: Microsoft, Codes: "550 5.7.515",
		Title:   "Outlook.com: high-volume sender authentication required",
		Meaning: "Domains sending more than 5,000 messages a day to Outlook.com must pass SPF and DKIM and publish DMARC (p=none or stricter); otherwise Outlook.com rejects the mail.",
		Steps: []string{
			"Run postsleuth dns YOUR-DOMAIN --ip YOUR-SENDING-IP and fix every SPF, DKIM and DMARC failure it reports.",
			"Make sure every message is DKIM-signed: the milter must be in smtpd_milters and non_smtpd_milters.",
			"Align the From: domain with the SPF or DKIM domain so DMARC passes.",
			"These are bounces: resend once the checks pass.",
		},
		Refs: []Ref{refMSTroubleshoot, refMSPolicies},
		re:   regexp.MustCompile(`(?i)\b(5\.7\.515)\b`),
	},
	{
		ID: "microsoft-exo-relay", Provider: Microsoft, Codes: "550 5.7.705 / 5.7.708 / 5.7.750",
		Title:   "Exchange Online refused mail relayed through a Microsoft 365 tenant",
		Meaning: "Exchange Online returns these when Postfix relays through a Microsoft 365 tenant (relayhost smtp.office365.com or a connector). Only that tenant's admin can clear them.",
		Steps: []string{
			"5.7.750: add and verify every sender domain Postfix uses as an accepted domain in Microsoft 365, or use a certificate-based connector, and check for unexpected connectors.",
			"5.7.705: look for a compromised on-premises server or connector, fix it, then ask Microsoft Support to lift the block.",
			"5.7.708: the IP has low reputation; on a trial tenant, ask Microsoft Support for an IP exception until licences are assigned.",
		},
		Refs: []Ref{refEXONDR},
		CodeNotes: map[string]string{
			"5.7.705": "the tenant exceeded its spam/bulk threshold; often a compromised server or connector",
			"5.7.708": "traffic not accepted from this IP: low IP reputation, common on new or trial tenants",
			"5.7.750": "large volume from a domain that isn't an accepted domain in the tenant, or a misconfigured connector",
		},
		re: regexp.MustCompile(`(?i)\b(5\.7\.70[58]|5\.7\.750)\b`),
	},

	// ---------------------------------------------------------------- Yahoo
	{
		ID: "yahoo-tss09", Provider: Yahoo, Codes: "[TSS09]",
		Title:   "Yahoo: IP permanently deferred",
		Meaning: "Yahoo has stopped accepting mail from this IP; the reply itself says retrying will not succeed. Postfix still retries until maximal_queue_lifetime unless you stop it.",
		Steps: []string{
			"Stop retrying Yahoo-bound mail while you fix the cause: put it on hold (postsleuth hold --allow-mutations QUEUE_ID, or postsuper -h) and don't move it to another IP.",
			"Find the cause: complaints, mail to old or bought lists, or a compromised account or script (postsleuth queue --list --domain yahoo.com).",
			"Enrol your DKIM domain in Yahoo's Complaint Feedback Loop and remove everyone who reports you.",
			"Meet the sender requirements: SPF or DKIM for every sender; SPF, DKIM and DMARC for bulk senders (postsleuth dns).",
			"Then submit a sender support request on Yahoo Sender Hub with the IP, the DKIM domain, the full reply and what you changed.",
		},
		Refs:      []Ref{refYahooTS, refYahooCFL, refYahooReqs, refYahooContact},
		re:        regexp.MustCompile(`(?i)\[(TSS09)\]|retrying will not succeed|permanently deferred`),
		permanent: true,
	},
	{
		ID: "yahoo-deferred", Provider: Yahoo, Codes: "421 4.7.0 [TSS04] and other [TS*]",
		Title:   "Yahoo is deferring your mail (complaints, volume or reputation)",
		Meaning: "Yahoo is deferring mail from your IP because of user complaints, spam-like content, a poor reputation of the IP or its subnet, or unusual traffic. Postfix retries on its own.",
		Steps: []string{
			"Let Postfix back off. " + noFlush + " Don't move the mail to other IPs.",
			"Slow down to Yahoo: yahoo.com, aol.com, ymail.com and the rest share your reputation, but Postfix limits concurrency per domain. A dedicated transport with a small process limit in master.cf (e.g. yahoo unix - - n - 2 smtp) caps them together.",
			"Find what changed: a volume spike, a new IP, complaints about a campaign, or a compromised account (postsleuth queue --list --domain yahoo.com).",
			"Enrol your DKIM domain in Yahoo's Complaint Feedback Loop to see who reports you as spam, and stop mailing them.",
			"If the same deferral keeps coming for a long time, submit a sender support request with the error and the codes from your log.",
		},
		Refs: []Ref{refYahooTS, refYahooReqs, refYahooCFL, refYahooContact},
		re:   regexp.MustCompile(`(?i)\[(TSS?\d+)\]`),
	},
	{
		ID: "yahoo-blocklist", Provider: Yahoo, Codes: "553 5.7.1 [BL21] / [BL23]",
		Title:   "Yahoo refuses your IP because of a blocklist",
		Meaning: "Yahoo refuses connections from your IP because it is on a blocklist Yahoo uses; Yahoo's error page points to Spamhaus. These are permanent errors.",
		Steps: []string{
			"Look the IP up at Spamhaus and read why it is listed.",
			"Fix the cause before asking for removal: spam leaving this server, an open relay, or a dynamic/residential IP that shouldn't send directly (send through a relayhost).",
			"Request removal from the list's operator, then resend the bounced mail.",
			"On a shared IP (hosting, VPS), ask the provider for a clean one.",
		},
		Refs: []Ref{refYahoo5xx, refSpamhaus, refYahooContact},
		re:   regexp.MustCompile(`(?i)\[(BL\d+)\]`),
	},
	{
		ID: "yahoo-auth", Provider: Yahoo, Codes: "550 5.7.9 / 554 5.7.9 (authentication)",
		Title:   "Yahoo: mail failed authentication",
		Meaning: "Yahoo requires every sender to authenticate with SPF or DKIM; bulk senders need SPF and DKIM plus a DMARC policy. Mail that fails the From: domain's DMARC or DKIM policy is rejected.",
		Steps: []string{
			"Run postsleuth dns YOUR-DOMAIN --ip YOUR-SENDING-IP and fix SPF, DKIM and DMARC.",
			"Make sure every message is DKIM-signed: the milter must be in smtpd_milters and non_smtpd_milters.",
			"Mailing lists: put the list's address in From: and the author in Reply-To:, or DMARC fails for authors at strict domains.",
			"If you forward mail, consider adding ARC.",
			"5xx rejections are not retried: resend after fixing.",
		},
		Refs: []Ref{refYahooAuth, refYahooReqs},
		re:   regexp.MustCompile(`(?i)\b(5\.7\.9)\b.*\b(?:unauthenticated|authenticat\w*)\b|\bunauthenticated\b|\bDMARC\b`),
	},
	{
		ID: "yahoo-policy", Provider: Yahoo, Codes: "554 5.7.9, [PH*]",
		Title:   "Yahoo rejected the message for policy reasons",
		Meaning: "Yahoo rejected the message for a policy reason: content (PH* codes: malware, phishing, ransomware or links to them), headers that aren't RFC 5322 compliant, or other characteristics Yahoo won't accept.",
		Steps: []string{
			"Check the content and every link: Yahoo blocks viruses, phishing, ransomware and links to them.",
			"Check the headers are RFC 5322 compliant: no duplicate or malformed headers, decodable From: and Subject:, a sane Date:.",
			"Check DMARC alignment with postsleuth dns.",
			"Look for spam leaving this server (postsleuth queue --list --domain yahoo.com).",
			"5xx rejections are not retried: resend after fixing. If you think it's a mistake, submit a sender support request.",
		},
		Refs: []Ref{refYahooPolicy, refYahoo5xx, refYahooReqs, refYahooContact},
		re:   regexp.MustCompile(`(?i)\[(PH\d+)\]|\b(5\.7\.9)\b|not accepted for policy reasons`),
	},
}
