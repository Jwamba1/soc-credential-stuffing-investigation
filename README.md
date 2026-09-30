Credential Stuffing Investigation: KQL + ServiceNow
I built this project to practice the work a SOC analyst actually does day to day: start with raw logs, find something suspicious, figure out what really happened, and write it up as a proper incident ticket.

I used the free security sample data Microsoft provides in Azure Data Explorer. What I found turned out to be more interesting than I expected, and I got a couple of things wrong along the way. I've kept those in, because working through them was the most useful part.


The short version
Two external IP addresses attacked a mail server over one week in January 2022. Between them they tried to log in to 36 different accounts, and 20 of those logins succeeded. That's a 56% success rate, which is very high for this kind of attack. It suggests the attacker already had accurate, recently stolen passwords.





Attack type
Credential stuffing
Attacker IPs
88.150.11.111, 149.124.195.189
Target
MAIL-SERVER01
Timeframe
2022-01-04 to 2022-01-11
Accounts compromised
20
Verdict
True positive



Tools
Azure Data Explorer (free cluster) to run the queries
KQL (Kusto Query Language) for hunting through the logs
ServiceNow Personal Developer Instance to document the incident
NIST SP 800-61 as the triage framework

Data source: the SecurityLogs sample database on Microsoft's public help.kusto.windows.net cluster. All users, hosts and IPs are fictional.


How I investigated it
1. Getting to know the data
Before hunting for anything, I wanted to know what I was working with. I listed the tables, then checked the structure of the login table.

.show tables

AuthenticationEvents

| getschema

The table records each login with a timestamp, host, source IP, user agent, username, result, and password hash. Every column was stored as text, which is worth knowing before you try to do anything with dates.

Next I checked what the result column actually contains, so my filters would match exactly:

AuthenticationEvents

| summarize count() by result

There were 1,692 successful logins and 2,177 failed ones. More failures than successes was the first thing that made me think something was off.
2. Looking for suspicious IPs
I grouped failed logins by source IP and counted how many different accounts each IP had tried.

AuthenticationEvents

| where result == "Failed Login"

| summarize Failures = count(), UsersTargeted = dcount(username) by src_ip

| top 10 by Failures

Two IPs stood out right away. Both were external, and both had failed exactly once per account across many different accounts. Everything else came from internal 192.168.x.x addresses and touched only one user each, which looks like ordinary people mistyping their own passwords.


3. Checking whether they got in
This was the question that mattered most. I pulled every login attempt from both IPs in time order:

AuthenticationEvents

| where src_ip in ("88.150.11.111", "149.124.195.189")

| project timestamp, src_ip, username, result, hostname, user_agent, password_hash

| sort by timestamp asc

A lot of them succeeded. A few other details stood out:

Every attempt targeted MAIL-SERVER01, so the goal was email access.
Every password hash was different. This is where I had to change my mind (more below).
The user agents were things like Windows 98 and Firefox 3.8. Nobody is really browsing with those, so it's almost certainly an automated tool faking its identity.


4. Building the list of compromised accounts
AuthenticationEvents

| where src_ip in ("88.150.11.111", "149.124.195.189")

| where result == "Successful Login"

| summarize FirstCompromise = min(timestamp), Logins = count() by username, src_ip

| sort by FirstCompromise asc

This gave me 20 accounts, each with exactly one successful login. The attacker got in, confirmed the password worked, and moved on to the next one.


5. Making sure I hadn't missed anyone
My first hunt only looked at failed logins. That bothered me, because an attacker with a valid password would never fail, and that search would never catch them. So I re-ran the hunt across all external IPs, ranked by how many accounts each one touched, successes included.

AuthenticationEvents

| where not(src_ip startswith "192.168.")

| summarize Attempts = count(), UsersTargeted = dcount(username), Successes = countif(result == "Successful Login") by src_ip

| top 10 by UsersTargeted

Only the same two IPs showed multi-account behavior. Every other external IP touched a single account. That gave me a lot more confidence that the scope was complete.




Things I got wrong (and fixed)
I first thought it was password spraying. One attempt per account across many accounts is the classic spraying pattern, where an attacker tries one common password everywhere. But spraying reuses the same password, and here every hash was different. That means the attacker had a separate, specific password for each user. That's credential stuffing: using username and password pairs that were already stolen somewhere else.

I undercounted the victims at first. My early results showed 13 compromised accounts, because the rest were cut off below the edge of the screen. When the numbers didn't add up (36 attempts minus 16 failures should be 20), I went back and found the other 7. Lesson learned: always check the record count, not just what's visible.

I chased a phishing theory that didn't hold up. The Email table had entries from the day before the attack started, and I wondered whether a phishing email had been used to steal the credentials. When I dug in, the columns didn't match their labels. The "subject" column held usernames and "recipient" held browser user agents. The timestamps lined up to the microsecond with the login records, so the table turned out to be mislabeled authentication data, not real emails. I couldn't confirm phishing, so I noted it as investigated but unconfirmed rather than forcing a conclusion.


The incident ticket
I documented the investigation in ServiceNow using the NIST 800-61 phases, with separate work notes for:

Detection & Analysis: how it was found and why it's a true positive
Scope: all 20 accounts, split by attacker IP
Containment & Recommendations: what to do now and how to prevent it

The full text is in incident-notes.txt.


What I'd recommend
Right away

Block both IPs at the firewall
Reset passwords and end active sessions for all 20 accounts
Check affected mailboxes for forwarding rules or other changes the attacker might have left behind

Longer term

Require MFA for mail access. This alone would have stopped the attack.
Add a detection rule that alerts when one external IP tries to log in to more than 5 accounts within 24 hours
Check whether the stolen credentials appear in known breach data


What I took away from this
Don't only hunt for failures. The most dangerous attackers are the ones whose logins work.
Let the evidence change your mind. My first theory was reasonable but wrong, and the password hashes are what showed me that.
Don't trust column names blindly. Real data is messy, so check what's actually in a column before building conclusions on it.
Numbers should reconcile. When totals don't add up, something is missing.


Repo contents
File
What it is
incident-notes.txt
Full ServiceNow work notes and resolution
kql-queries.txt
Every query I ran, in order
screenshots/
Evidence from each stage of the investigation


