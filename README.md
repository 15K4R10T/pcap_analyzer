# Manuals 

you can using this tools with shell (dont forget to chmod +x the tools)

# File to analyze
PCAP_FILE="log_analysis_5.pcapng" (editing this for your pcap file)

<pre>
  ./pcap_analyzer2.sh

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                  PCAP/PCAPNG NETWORK ANALYZER                    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

File: log_analysis_5.pcapng
Date: Min 18 Mei 2025 12:38:40  WIB


┌──────────────────────────────────────────────────────────────────────┐
│ PROTOKOL SERVICE YANG DITEMUKAN                                      │
└──────────────────────────────────────────────────────────────────────┘

17066 eth:ethertype:ip:tcp
6643 eth:ethertype:ip:tcp:ssh
2262 eth:ethertype:ip:tcp:http:data-text-lines
2262 eth:ethertype:ip:tcp:http
950  eth:ethertype:ip:udp:quic
517  eth:ethertype:ip:udp:data
231  eth:ethertype:ip:tcp:tls
70   eth:ethertype:ipv6:icmpv6
38   eth:ethertype:ip:tcp:data
37   eth:ethertype:ipv6:udp:mdns
37   eth:ethertype:arp
36   eth:ethertype:ip:udp:mdns
31   eth:ethertype:ip:udp:quic:tls
15   eth:ethertype:ip:udp:ssdp
12   eth:ethertype:ip:udp:dns
5    eth:ethertype:ip:tcp:tls:tls
5    eth:ethertype:ip:tcp:ftp
2    eth:ethertype:ip:tcp:tls:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:tls:x509ce:x509ce:pkix1implicit:x509ce:x509ce:x509ce:x509ce:x509ce:x509ce:pkix1explicit:x509ce:x509ce:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509ce:x509ce:x509ce:x509ce:x509ce:pkix1implicit:x509ce:x509ce:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509ce:x509ce:x509ce
2    eth:ethertype:ip:tcp:tls:ocsp:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509ce:x509ce:x509ce:x509ce:x509ce:x509ce:x509ce:ocsp
1    eth:ethertype:ip:tcp:tls:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:tls:x509ce:x509ce:pkix1implicit:x509ce:x509ce:x509ce:x509ce:x509ce:x509ce:pkix1explicit:x509ce:x509ce:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509ce:x509ce:x509ce:x509ce:x509ce:pkix1implicit:x509ce:x509ce:ocsp:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509sat:x509ce:x509ce:x509ce:x509ce:x509ce:x509ce:x509ce:ocsp

┌──────────────────────────────────────────────────────────────────────┐
│ PORT TCP/UDP YANG DIGUNAKAN                                          │
└──────────────────────────────────────────────────────────────────────┘

» Top 20 Ports
──────────────────────────────────────────────────
10732 Port: 22,52311
7056 Port: 52311,22
252  Port: 62122,443
250  Port: 57544,443
212  Port: 39920,80
212  Port: 39862,80
212  Port: 32968,80
210  Port: 39914,80
210  Port: 39910,80
210  Port: 39894,80
210  Port: 39890,80
210  Port: 39880,80
210  Port: 39850,80
210  Port: 39848,80
210  Port: 33038,80
210  Port: 33032,80
210  Port: 33026,80
210  Port: 33010,80
210  Port: 33002,80
210  Port: 32986,80

┌──────────────────────────────────────────────────────────────────────┐
│ FILE TRANSFERS                                                       │
└──────────────────────────────────────────────────────────────────────┘

» FTP Transfers
──────────────────────────────────────────────────
STOR  malware
» HTTP Transfers
──────────────────────────────────────────────────
3    GET  /.web
3    GET  /_vti_bin/_vti_aut/author.dll
3    GET  /_vti_bin/_vti_adm/admin.dll
3    GET  /_vti_bin/shtml.dll
3    GET  /.swf
3    GET  /.svn
3    GET  /.ssh
3    GET  /.perf
3    GET  /.hta
3    GET  /.cvs
3    GET  /admin.pl
3    GET  /admin.php
3    GET  /admin.cgi
2    GET  /awstats.conf
2    GET  /AT-admin.cgi
2    GET  /application.wadl
2    GET  /akeeba.backend.log
1    GET  /crossdomain.xml
1    GET  /catalog.wci
1    GET  /cachemgr.cgi
» SMB Transfers
──────────────────────────────────────────────────
No SMB transfers detected

┌──────────────────────────────────────────────────────────────────────┐
│ DNS QUERIES                                                          │
└──────────────────────────────────────────────────────────────────────┘

3    my.microsoftpersonalcontent.com
3    ecs.office.com
3    clients6.google.com
3    chatgpt.com

┌──────────────────────────────────────────────────────────────────────┐
│ HTTP USER AGENTS                                                     │
└──────────────────────────────────────────────────────────────────────┘

2262 62 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)

┌──────────────────────────────────────────────────────────────────────┐
│ EMAIL PROTOCOLS (SMTP/POP/IMAP)                                      │
└──────────────────────────────────────────────────────────────────────┘

tshark: Some fields aren't valid:
	imap.req.command
No email protocol traffic detected

┌──────────────────────────────────────────────────────────────────────┐
│ SSH CONNECTIONS                                                      │
└──────────────────────────────────────────────────────────────────────┘

5362 Source: 192.168.18.6   :22    → Destination: 192.168.18.230 :52311
1281 Source: 192.168.18.230 :52311 → Destination: 192.168.18.6   :22   

┌──────────────────────────────────────────────────────────────────────┐
│ POTENTIAL FILE REFERENCES IN PACKETS                                 │
└──────────────────────────────────────────────────────────────────────┘

No file references detected

┌──────────────────────────────────────────────────────────────────────┐
│ POTENTIAL SERVICE:FILE COMBINATIONS                                  │
└──────────────────────────────────────────────────────────────────────┘

» FTP Files
──────────────────────────────────────────────────
ftp:malware
» HTTP Files
──────────────────────────────────────────────────
http:/admin.cgi
http:/admin.php
http:/admin.pl
http:/akeeba.backend.log
http:/application.wadl
http:/AT-admin.cgi
http:/awstats.conf
http:/cachemgr.cgi
http:/catalog.wci
http:/crossdomain.xml
http:/.cvs
http:/.hta
http:/.perf
http:/.ssh
http:/.svn
http:/.swf
http:/_vti_bin/shtml.dll
http:/_vti_bin/_vti_adm/admin.dll
http:/_vti_bin/_vti_aut/author.dll
http:/.web
» SMB Files
──────────────────────────────────────────────────
No SMB files detected
./pcap_analyzer2.sh: line 233: extract_objects: command not found

┌──────────────────────────────────────────────────────────────────────┐
│ SEARCHING FOR SERVICE:FILE STRINGS                                   │
└──────────────────────────────────────────────────────────────────────┘

No service:file strings detected

┌──────────────────────────────────────────────────────────────────────┐
│ ANALISIS SUMMARY                                                     │
└──────────────────────────────────────────────────────────────────────┘

Analisis selesai pada: Min 18 Mei 2025 12:38:48  WIB
File yang dianalisis: log_analysis_5.pcapng
HTTP Objects: 9144 files
FTP-DATA Objects: 0 files

Analisis selesai! Periksa hasil di atas untuk kombinasi service:file yang relevan.

</pre>
