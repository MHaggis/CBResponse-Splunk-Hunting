# Carbon Black Response - Splunk Hunting

Analyzing Carbon Black Response endpoint telemetry in Splunk

### Stats

    | metadata type=sourcetypes index=carbonblack

<br>

    `cb`
    |  stats values(computer_name)

<br>

    `cb` type=alert
    | stats values(docs{}.endpoint) by watchlist_name

<br>

    `cb` notification_type="watchlist.hit.* "
    | stats values(watchlist_name)

<br>

    `cb`
    | stats values(feed_name)

<br>

    `cb`
    | stats count by feed_name

<br>

    `cb` notification_type=feed.*
    | stats values(feed_name) count by computer_name

<br>

    `cb`
    | stats values(type)

### Black Box Hunting

#### Critical Process Check

<i>by process:

    `cb` process="powershell.exe" OR process="msbuild.exe" OR process="psexec.exe" OR process="at.exe" OR process="schtasks.exe" OR process="net.exe" OR process="vssadmin.exe" OR process="utilman.exe" OR process="wmic.exe" OR process="mshta.exe" OR process="wscript.exe" OR process="cscript.exe" OR process="cmd.exe" OR process="whoami.exe" OR process="mmc.exe" OR process="systeminfo.exe" OR process="csvde.exe" OR process="certutil.exe"
    | stats values(command_line) by process

<b>Critical Process Check by computer

    `cb` process="powershell.exe" OR process="msbuild.exe" OR process="psexec.exe" OR process="at.exe" OR process="schtasks.exe" OR process="net.exe" OR process="vssadmin.exe" OR process="utilman.exe" OR process="wmic.exe" OR process="mshta.exe" OR process="wscript.exe" OR process="cscript.exe" OR process="cmd.exe" OR process="whoami.exe" OR process="mmc.exe" OR process="systeminfo.exe" OR process="csvde.exe" OR process="certutil.exe"
    | stats values(command_line) by computer_name

#### Endpoint Deep Dive

    `cb` computer_name=collider01  type="ingress.event.procstart" | stats values(command_line) by process

<br>

    `cb` process=net.exe
    | stats values(computer_name) by date_hour

<br>

    `cb` process=net.exe
    | stats values(command_line) by date_hour

<br>

    `cb` process=net.exe | stats values(command_line) by computer_name

<br>

    `cb` process=net.exe localgroup | stats count values(command_line) by computer_name,username

<br>

    `cb` process=powershell.exe | stats count values(path)

<br>

    `cb` process=powershell.exe
    | eval length=len(command_line)
    | fillnull value=0 length
    | stats values(command_line) by length

Identify lengths greater than:

    | where length > 1000

<br>

Use regex to identify a numerical process

    `cb`
    | rex "(?<numeric_process>[0-9]{3,15}\.exe)"
    | stats values(numeric_process)


### Feeds, Watchlist Alerts

    `cb` feed_name=bit9endpointvisibility
    | stats values(ioc_query_string) by docs{}.cmdline

<br>

    `cb`
    | stats values(feed_name)

<br>

    `cb`
    | stats count by feed_name

<br>

    `cb` type=alert
    |  stats values(docs{}.endpoint) by watchlist_name

<br>

    `cb` type=alert
    | stats values(feed_name) count by computer_name


### Username Analysis

    `cb`
    | stats values(username) count by computer_name

<br>

    `cb`
    | stats values(computer_name) count by username

<br>

    `cb` [ inputlookup adminaccounts ]
    | stats values(username) count

<br>

    `cb`
    | stats dc(username) count by computer_name

<br>

    `cb`
    | stats dc(computer_name) count by username

<br>

    `cb` username!=SYSTEM username!="LOCAL SERVICE" username!="NETWORK SERVICE"
    | stats dc(computer_name) count by username

<br>

    `cb` username!=SYSTEM username!="LOCAL SERVICE" username!="NETWORK SERVICE"
    | stats dc(computer_name) as computers count by username
    | where computers > 2

<br>

    `cb` [inputlookup svc_accounts]
    | stats dc(computer_name) as computers count by username
    | where computers > 2
    | table username, computers

### Network Analysis

    `cb` computer_name=collider01  type="ingress.event.netconn" direction="outbound"
    | stats count by remote_port

<br>

    `cb` type="ingress.event.netconn" direction="outbound"
    | stats count by remote_port

<br>

    `cb` type="ingress.event.netconn" direction="outbound"
    | stats dc(remote_port) by local_port

<br>

    `cb` type="ingress.event.netconn" direction="outbound"
    | stats dc(local_port) by remote_port

<br>

    `cb` type="ingress.event.netconn"
    | iplocation remote_ip AS geoip
    | stats values(City) by computer_name

<br>

    `cb` type="ingress.event.netconn"
    | eval length=len(domain)
    | fillnull value=0 length
    | stats values(domain) by length

<br>

    `cb` type="ingress.event.netconn"
    | eval length=len(domain)
    | fillnull value=0 length
    | stats values(domain) by length
    | where length < 10

<br>

    `cb` type="ingress.event.netconn" NOT (remote_port=80 OR remote_port=443)
    | stats values(domain) by remote_port

<br>

    `cb` type="ingress.event.netconn"
    | stats values(domain) by remote_port

<br>

    `cb` type="ingress.event.netconn" (remote_port=21 OR remote_port=587 OR remote_port=25 OR remote_port=6667)
    | stats values(domain) by computer_name

<br>

    `cb` type="ingress.event.netconn" (remote_port=25 OR remote_port=587)
    | stats values(remote_port) count by computer_name
