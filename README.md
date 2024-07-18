# Port Scan
```
###################################
# Author: Ibrar Ansari
# Date: 18-07-2024
# Version: 1
#
# Search TAG: port scanner , scan port , scan ports , ports scan , port scan , ports scanner , ip port scanner , ip ports scanner 
# This is Port scanner app
###################################
```

# What is the difference between unicast, anycast, broadcast and multicast traffic?
```
------------------------------------------------------------
| TYPE      | ASSOCIATIONS     | SCOPE           | EXAMPLE |
------------------------------------------------------------
| Unicast   | 1 to 1           | Whole network   | HTTP    | 
------------------------------------------------------------
| Broadcast | 1 to Many/ALL    | Subnet          | ARP/dhcp|
------------------------------------------------------------
| Multicast | One/Many to Many | Defined horizon | SLP/IPTV|
------------------------------------------------------------
| Anycast   | Many to Few      | Whole network   | 6to4/dns|
------------------------------------------------------------
```

# Protocol information
```
websocket = A websocket connects to a server via a single TCP/IP connection and performs both full-duplex and bifunctional communication
```

# LIST OF WELL-KNOWN PORTS
```
Port Description
1	TCP Port Service Multiplexer (TCPMUX)
5	Remote Job Entry (RJE)
7	ECHO
18	Message Send Protocol (MSP)
20	FTP — Data
21	FTP — Control
22	SSH Remote Login Protocol
23	Telnet
25	Simple Mail Transfer Protocol (SMTP)
29	MSG ICP
37	Time
42	Host Name Server (Nameserv)
43	WhoIs
49	Login Host Protocol (Login)
53	Domain Name System (DNS)
69	Trivial File Transfer Protocol (TFTP)
70	Gopher Services
79	Finger
80	HTTP
103	X.400 Standard
108	SNA Gateway Access Server
109	POP2
110	POP3
115	Simple File Transfer Protocol (SFTP)
118	SQL Services
119	Newsgroup (NNTP)
137	NetBIOS Name Service
139	NetBIOS Datagram Service
143	Interim Mail Access Protocol (IMAP)
150	NetBIOS Session Service
156	SQL Server
161	SNMP
179	Border Gateway Protocol (BGP)
190	Gateway Access Control Protocol (GACP)
194	Internet Relay Chat (IRC)
197	Directory Location Service (DLS)
389	Lightweight Directory Access Protocol (LDAP)
396	Novell Netware over IP
443	HTTPS
444	Simple Network Paging Protocol (SNPP)
445	Microsoft-DS
458	Apple QuickTime
546	DHCP Client
547	DHCP Server
563	SNEWS
569	MSN
3306 MySQL
3389 RDP
1433 MSSQL
1080 Socks
5432 Postgres
```
# LIST OF WELL-KNOWN PORTS IN DETAILS
```
Well-known ports
The port numbers in the range from 0 to 1023 are the well-known ports or system ports. They are used by system processes that provide widely used types of network services. On Unix-like operating systems, a process must execute with superuser privileges to be able to bind a network socket to an IP address using one of the well-known ports.

Port	TCP	UDP	Description	Status
0	TCP		Programming technique for specifying system-allocated (dynamic) ports	Unofficial
0		UDP	Reserved	Official
1	TCP	UDP	TCP Port Service Multiplexer (TCPMUX)	Official
2	TCP	UDP	CompressNET Management Utility	Official
3	TCP	UDP	CompressNET Compression Process	Official
4	TCP	UDP	Unassigned	Official
5	TCP	UDP	Remote Job Entry	Official
6	TCP	UDP	Unassigned	Official
7	TCP	UDP	Echo Protocol	Official
8	TCP	UDP	Unassigned	Official
9	TCP	UDP	Discard Protocol	Official
9		UDP	Wake-on-LAN	Unofficial
10	TCP	UDP	Unassigned	Official
11	TCP	UDP	Active Users (systat service)	Official
12	TCP	UDP	Unassigned	Official
13	TCP	UDP	Daytime Protocol (RFC 867)	Official
14	TCP	UDP	Unassigned	Official
15	TCP	UDP	Previously netstat service	Unofficial
16	TCP	UDP	Unassigned	Official
17	TCP	UDP	Quote of the Day	Official
18	TCP	UDP	Message Send Protocol	Unofficial
19	TCP	UDP	Character Generator Protocol (CHARGEN)	Unofficial
20	TCP	UDP	FTP data transfer	Official
21	TCP, SCTP	UDP	FTP control (command)	Official
22	TCP, SCTP	UDP	Secure Shell (SSH)—used for secure logins, file transfers (scp, sftp) and port forwarding	Official
23	TCP	UDP	Telnet protocol—unencrypted text communications	Official
24	TCP	UDP	Priv-mail : any private mail system.	Official
25	TCP	UDP	Simple Mail Transfer Protocol (SMTP)—used for e-mail routing between mail servers	Official
26	TCP	UDP	Unassigned	Official
27	TCP	UDP	NSW User System FE	Official
29	TCP	UDP	MSG ICP	Official
33	TCP	UDP	Display Support Protocol	Official
35	TCP	UDP	Any private printer server protocol	Official
37	TCP	UDP	TIME protocol	Official
39	TCP	UDP	Resource Location Protocol (RLP)—used for determining the location of higher level services from hosts on a network	Official
40	TCP	UDP	Unassigned	Official
42	TCP	UDP	ARPA Host Name Server Protocol	Official
42	TCP	UDP	Windows Internet Name Service	Unofficial
43	TCP	UDP	WHOIS protocol	Official
47	TCP	UDP	NI FTP	Official
49	TCP	UDP	TACACS+ Login Host protocol	Official
50	TCP	UDP	ESP	Official
51	TCP	UDP	IMP Logical Address Maintenance	Official
52	TCP	UDP	XNS (Xerox Network Systems) Time Protocol	Official
53	TCP	UDP	Domain Name System (DNS)	Official
54	TCP	UDP	XNS (Xerox Network Systems) Clearinghouse	Official
55	TCP	UDP	ISI Graphics Language (ISI-GL)	Official
56	TCP	UDP	XNS (Xerox Network Systems) Authentication	Official
56	TCP	UDP	Route Access Protocol (RAP)	Unofficial
57	TCP	UDP	any private terminal access	Official
58	TCP	UDP	XNS (Xerox Network Systems) Mail	Official
64	TCP	UDP	CI (Travelport) (formerly Covia) Comms Integrator	Official
67	TCP	UDP	Bootstrap Protocol (BOOTP) Server; also used by Dynamic Host Configuration Protocol (DHCP)	Official
68	TCP	UDP	Bootstrap Protocol (BOOTP) Client; also used by Dynamic Host Configuration Protocol (DHCP)	Official
69	TCP	UDP	Trivial File Transfer Protocol (TFTP)	Official
70	TCP	UDP	Gopher protocol	Official
71	TCP	UDP	NETRJS protocol	Official
72	TCP	UDP	NETRJS protocol	Official
73	TCP	UDP	NETRJS protocol	Official
74	TCP	UDP	NETRJS protocol	Official
77	TCP	UDP	Any private Remote Job Entry	Official
79	TCP	UDP	Finger protocol	Official
80	TCP, SCTP	UDP	Hypertext Transfer Protocol (HTTP)	Official
80		UDP	QUIC (from Chromium) for HTTP	Unofficial
81	TCP		Torpark—Onion routing	Unofficial
82		UDP	Torpark—Control	Unofficial
88	TCP	UDP	Kerberos—authentication system	Official
90	TCP	UDP	dnsix (DoD Network Security for Information Exchange) Security Attribute Token Map	Official
90	TCP	UDP	PointCast (dotcom)	Unofficial
99	TCP		WIP Message protocol	Unofficial
100		UDP	CyberGate RAT protocol	Unofficial
101	TCP	UDP	NIC host name	Official
102	TCP	UDP	ISO-TSAP (Transport Service Access Point) Class 0 protocol; also used by Digital Equipment Corporation DECnet (Phase V+) over TCP/IP	Official
104	TCP	UDP	ACR/NEMA Digital Imaging and Communications in Medicine (DICOM)	Official
105	TCP	UDP	CCSO Nameserver Protocol (Qi/Ph)	Official
107	TCP	UDP	Remote TELNET Service protocol	Official
108	TCP	UDP	SNA Gateway Access Server	Official
109	TCP	UDP	Post Office Protocol v2 (POP2)	Official
110	TCP	UDP	Post Office Protocol v3 (POP3)	Official
111	TCP	UDP	ONC RPC (Sun RPC)	Official
113	TCP		Ident—Authentication Service/Identification Protocol, used by IRC servers to identify users	Official
113		UDP	Authentication Service (auth)	Official
115	TCP		Simple File Transfer Protocol	Official
117	STD		UUCP Path Service	Official
118	TCP	UDP	SQL (Structured Query Language) Services	Official
119	TCP		Network News Transfer Protocol (NNTP)—retrieval of newsgroup messages	Official
123	TCP	UDP	Network Time Protocol (NTP)—used for time synchronization	Official
126	TCP	UDP	Formerly Unisys Unitary Login, renamed by Unisys to NXEdit. Used by Unisys Programmer's Workbench for Clearpath MCP, an IDE for Unisys MCP software development	Official
135	TCP	UDP	DCE endpoint resolution	Official
135	TCP	UDP	Microsoft EPMAP (End Point Mapper), also known as DCE/RPC Locator service, used to remotely manage services including DHCP server, DNS server and WINS. Also used by DCOM	Unofficial
137	TCP	UDP	NetBIOS NetBIOS Name Service	Official
138	TCP	UDP	NetBIOS NetBIOS Datagram Service	Official
139	TCP	UDP	NetBIOS NetBIOS Session Service	Official
143	TCP		Internet Message Access Protocol (IMAP)—management of email messages	Official
152	TCP	UDP	Background File Transfer Program (BFTP)	Official
153	TCP	UDP	SGMP, Simple Gateway Monitoring Protocol	Official
156	TCP	UDP	SQL Service	Official
158	TCP	UDP	DMSP, Distributed Mail Service Protocol	Unofficial
161		UDP	Simple Network Management Protocol (SNMP)	Official
162	TCP	UDP	Simple Network Management Protocol Trap (SNMPTRAP)	Official
170	TCP		Print-srv, Network PostScript	Official
175	TCP		VMNET (IBM z/VM, z/OS & z/VSE—Network Job Entry (NJE))	Official
177	TCP	UDP	X Display Manager Control Protocol (XDMCP)	Official
179	TCP		BGP (Border Gateway Protocol)	Official
194	TCP	UDP	Internet Relay Chat (IRC)	Official
199	TCP	UDP	SMUX, SNMP Unix Multiplexer	Official
201	TCP	UDP	AppleTalk Routing Maintenance	Official
209	TCP	UDP	The Quick Mail Transfer Protocol	Official
210	TCP	UDP	ANSI Z39.50	Official
213	TCP	UDP	Internetwork Packet Exchange (IPX)	Official
218	TCP	UDP	Message posting protocol (MPP)	Official
220	TCP	UDP	Internet Message Access Protocol (IMAP), version 3	Official
259	TCP	UDP	ESRO, Efficient Short Remote Operations	Official
262	TCP	UDP	Arcisdms	Official
264	TCP	UDP	BGMP, Border Gateway Multicast Protocol	Official
280	TCP	UDP	http-mgmt	Official
300	TCP		ThinLinc Web Access	Unofficial
308	TCP		Novastor Online Backup	Official
311	TCP		Mac OS X Server Admin (officially AppleShare IP Web administration)	Official
318	TCP	UDP	PKIX TSP, Time Stamp Protocol	Official
319		UDP	Precision Time Protocol (PTP) event messages	Official
320		UDP	Precision Time Protocol (PTP) general messages	Official
350	TCP	UDP	MATIP-Type A, Mapping of Airline Traffic over Internet Protocol	Official
351	TCP	UDP	MATIP-Type B, Mapping of Airline Traffic over Internet Protocol	Official
356	TCP	UDP	cloanto-net-1 (used by Cloanto Amiga Explorer and VMs)	Official
366	TCP	UDP	ODMR, On-Demand Mail Relay	Official
369	TCP	UDP	Rpc2portmap	Official
370	TCP		codaauth2—Coda authentication server	Official
370		UDP	codaauth2—Coda authentication server	Official
370		UDP	securecast1—Outgoing packets to NAI's SecureCast servers As of 2000	Unofficial
371	TCP	UDP	ClearCase albd	Official
383	TCP	UDP	HP data alarm manager	Official
384	TCP	UDP	A Remote Network Server System	Official
387	TCP	UDP	AURP, AppleTalk Update-based Routing Protocol	Official
389	TCP	UDP	Lightweight Directory Access Protocol (LDAP)	Official
399	TCP	UDP	Digital Equipment Corporation DECnet (Phase V+) over TCP/IP	Official
401	TCP	UDP	UPS Uninterruptible Power Supply	Official
427	TCP	UDP	Service Location Protocol (SLP)	Official
433	TCP	UDP	NNSP, part of Network News Transfer Protocol	Official
434	TCP	UDP	Mobile IP Agent (RFC 5944)	Official
443	TCP, SCTP	UDP	Hypertext Transfer Protocol over TLS/SSL (HTTPS)	Official
443		UDP	QUIC (from Chromium) for HTTPS	Unofficial
444	TCP	UDP	SNPP, Simple Network Paging Protocol (RFC 1568)	Official
445	TCP		Microsoft-DS Active Directory, Windows shares	Official
445	TCP		Microsoft-DS SMB file sharing	Official
464	TCP	UDP	Kerberos Change/Set password	Official
465	TCP		URL Rendezvous Directory for SSM (Cisco protocol)	Official
465	TCP		Simple Mail Transfer Protocol over TLS/SSL (SMTPS)	Unofficial
475	TCP	UDP	tcpnethaspsrv (Aladdin Knowledge Systems Hasp services, TCP/IP version)	Official
491	TCP		GO-Global remote access and application publishing software	Unofficial
497	TCP		Dantz Retrospect	Official
500	TCP	UDP	Internet Security Association and Key Management Protocol (ISAKMP)	Official
502	TCP	UDP	Modbus Protocol	Official
504	TCP	UDP	Citadel—multiservice protocol for dedicated clients for the Citadel groupware system	Official
510	TCP	UDP	FirstClass Protocol (FCP), used by FirstClass client/server groupware system	Official
512	TCP		Rexec, Remote Process Execution	Official
512		UDP	comsat, together with biff	Official
513	TCP		rlogin	Official
513		UDP	Who	Official
514	TCP		Shell—used to execute non-interactive commands on a remote system (Remote Shell, rsh, remsh)	Official
514		UDP	Syslog—used for system logging	Official
515	TCP		Line Printer Daemon—print service	Official
517		UDP	Talk	Official
518		UDP	NTalk	Official
520	TCP		efs, extended file name server	Official
520		UDP	Routing Information Protocol (RIP)	Official
521		UDP	Routing Information Protocol Next Generation (RIPng)	Official
524	TCP	UDP	NetWare Core Protocol (NCP) is used for a variety things such as access to primary NetWare server resources, Time Synchronization, etc.	Official
525		UDP	Timed, Timeserver	Official
530	TCP	UDP	RPC	Official
531	TCP	UDP	AOL Instant Messenger	Unofficial
532	TCP		netnews	Official
533		UDP	netwall, For Emergency Broadcasts	Official
540	TCP		UUCP (Unix-to-Unix Copy Protocol)	Official
542	TCP	UDP	commerce (Commerce Applications)	Official
543	TCP		klogin, Kerberos login	Official
544	TCP		kshell, Kerberos Remote shell	Official
545	TCP		OSIsoft PI (VMS), OSISoft PI Server Client Access	Unofficial
546	TCP	UDP	DHCPv6 client	Official
547	TCP	UDP	DHCPv6 server	Official
548	TCP		Apple Filing Protocol (AFP) over TCP	Official
550	TCP	UDP	new-rwho, new-who	Official
554	TCP	UDP	Real Time Streaming Protocol (RTSP)	Official
556	TCP		Remotefs, RFS, rfs_server	Official
560		UDP	rmonitor, Remote Monitor	Official
561		UDP	monitor	Official
563	TCP	UDP	NNTP over TLS/SSL (NNTPS)	Official
564	TCP		Plan9	Unofficial
587	TCP		e-mail message submission (SMTP)	Official
591	TCP		FileMaker 6.0 (and later) Web Sharing (HTTP Alternate, also see port 80)	Official
593	TCP	UDP	HTTP RPC Ep Map, Remote procedure call over Hypertext Transfer Protocol, often used by Distributed Component Object Model services and Microsoft Exchange Server	Official
604	TCP		TUNNEL profile, a protocol for BEEP peers to form an application layer tunnel	Official
623		UDP	ASF Remote Management and Control Protocol (ASF-RMCP)	Official
625	TCP		Open Directory Proxy (ODProxy)	Unofficial
631	TCP	UDP	Internet Printing Protocol (IPP)	Official
631	TCP	UDP	Common Unix Printing System (CUPS) administration console (extension to IPP)	Unofficial
635	TCP	UDP	RLZ DBase	Official
636	TCP	UDP	Lightweight Directory Access Protocol over TLS/SSL (LDAPS)	Official
639	TCP	UDP	MSDP, Multicast Source Discovery Protocol	Official
641	TCP	UDP	SupportSoft Nexus Remote Command (control/listening): A proxy gateway connecting remote control traffic	Official
643	TCP	UDP	SANity	Official
646	TCP	UDP	LDP, Label Distribution Protocol, a routing protocol used in MPLS networks	Official
647	TCP		DHCP Failover protocol	Official
648	TCP		RRP (Registry Registrar Protocol)	Official
651	TCP	UDP	IEEE-MMS	Official
653	TCP	UDP	SupportSoft Nexus Remote Command (data): A proxy gateway connecting remote control traffic	Official
654	TCP		Media Management System (MMS) Media Management Protocol (MMP)	Official
655	TCP	UDP	Tinc VPN daemon	Unofficial
657	TCP	UDP	IBM RMC (Remote monitoring and Control) protocol, used by System p5 AIX Integrated Virtualization Manager (IVM) and Hardware Management Console to connect managed logical partitions (LPAR) to enable dynamic partition reconfiguration	Official
660	TCP		Mac OS X Server administration	Official
666	TCP	UDP	Doom, first online first-person shooter	Official
666	TCP		airserv-ng, aircrack-ng's server for remote-controlling wireless devices	Unofficial
674	TCP		ACAP (Application Configuration Access Protocol)	Official
688	TCP	UDP	REALM-RUSD (ApplianceWare Server Appliance Management Protocol)	Official
690	TCP	UDP	VATP (Velneo Application Transfer Protocol)	Official
691	TCP		MS Exchange Routing	Official
694	TCP	UDP	Linux-HA High availability Heartbeat	Official
695	TCP		IEEE-MMS-SSL (IEEE Media Management System over SSL)	Official
698		UDP	OLSR (Optimized Link State Routing)	Official
700	TCP		EPP (Extensible Provisioning Protocol), a protocol for communication between domain name registries and registrars (RFC 5734)	Official
701	TCP		LMP (Link Management Protocol (Internet)), a protocol that runs between a pair of nodes and is used to manage traffic engineering (TE) links	Official
702	TCP		IRIS (Internet Registry Information Service) over BEEP (Blocks Extensible Exchange Protocol) (RFC 3983)	Official
706	TCP		Secure Internet Live Conferencing (SILC)	Official
711	TCP		Cisco Tag Distribution Protocol —being replaced by the MPLS Label Distribution Protocol	Official
712	TCP		Topology Broadcast based on Reverse-Path Forwarding routing protocol (TBRPF) (RFC 3684)	Official
749	TCP	UDP	Kerberos (protocol) administration	Official
750		UDP	kerberos-iv, Kerberos version IV	Official
751	TCP	UDP	kerberos_master, Kerberos authentication	Unofficial
752		UDP	passwd_server, Kerberos Password (kpasswd) server	Unofficial
753	TCP		Reverse Routing Header (rrh)	Official
753		UDP	Reverse Routing Header (rrh)	Official
753		UDP	userreg_server, Kerberos userreg server	Unofficial
754	TCP		tell send	Official
754	TCP		krb5_prop, Kerberos v5 slave propagation	Unofficial
754		UDP	tell send	Official
760	TCP	UDP	krbupdate [kreg], Kerberos registration	Unofficial
782	TCP		Conserver serial-console management server	Unofficial
783	TCP		SpamAssassin spamd daemon	Unofficial
800		UDP	mdbe daemon	Official
808	TCP		Microsoft Net.TCP Port Sharing Service	Unofficial
829	TCP		Certificate Management Protocol	Unofficial
843	TCP		Adobe Flash	Unofficial
847	TCP		DHCP Failover protocol	Official
848	TCP	UDP	Group Domain Of Interpretation (GDOI) protocol	Official
860	TCP		iSCSI (RFC 3720)	Official
861	TCP	UDP	OWAMP control (RFC 4656)	Official
862	TCP	UDP	TWAMP control (RFC 5357)	Official
873	TCP		rsync file synchronization protocol	Official
888	TCP		cddbp, CD DataBase (CDDB) protocol (CDDBP), IBM Endpoint Manager Remote Control	Unofficial
897	TCP	UDP	Brocade SMI-S RPC	Unofficial
898	TCP	UDP	Brocade SMI-S RPC SSL	Unofficial
901	TCP		Samba Web Administration Tool (SWAT)	Unofficial
901	TCP	UDP	VMware Virtual Infrastructure Client (from managed device to management console)	Unofficial
902	TCP	UDP	ideafarm-door (IdeaFarm (tm) Operations)	Official
902	TCP	UDP	VMware Server Console (from management console to managed device)	Unofficial
903	TCP	UDP	ideafarm-panic (IdeaFarm (tm) Operations)	Official
903	TCP		VMware Remote Console	Unofficial
904	TCP		VMware Server Alternate (if 902 is in use, i.e. SUSE linux)	Unofficial
911	TCP		Network Console on Acid (NCA)—local tty redirection over OpenSSH	Unofficial
944		UDP	Network File System Service	Unofficial
953	TCP	UDP	Domain Name System (DNS) RNDC Service	Unofficial
973		UDP	Network File System over IPv6 Service	Unofficial
981	TCP		SofaWare Technologies Remote HTTPS management for firewall devices running embedded Check Point FireWall-1 software	Unofficial
987	TCP		Microsoft Windows SBS SharePoint	Unofficial
989	TCP	UDP	FTPS Protocol (data): FTP over TLS/SSL	Official
990	TCP	UDP	FTPS Protocol (control): FTP over TLS/SSL	Official
991	TCP	UDP	NAS (Netnews Administration System)	Official
992	TCP	UDP	TELNET protocol over TLS/SSL	Official
993	TCP		Internet Message Access Protocol over TLS/SSL (IMAPS)	Official
994	TCP	UDP	Internet Relay Chat over TLS/SSL (IRCS)	Official
995	TCP		Post Office Protocol 3 over TLS/SSL (POP3S)	Official
999	TCP		ScimoreDB Database System	Unofficial
1002	TCP		Opsware agent (aka cogbot)	Unofficial
1010	TCP		ThinLinc Web Administration	Unofficial
1023	TCP	UDP	Reserved	Official
```
