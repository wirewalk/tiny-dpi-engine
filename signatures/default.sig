# tiny-dpi-engine default signature database
# Format: PROTOCOL: pattern_string
#
# Lines starting with # are comments.
# Patterns are matched against packet payload (TCP/UDP data).
# Aho-Corasick multi-pattern matching is used.

# HTTP
HTTP: GET 
HTTP: POST 
HTTP: PUT 
HTTP: HEAD 
HTTP: DELETE 
HTTP: OPTIONS 
HTTP: HTTP/1.0
HTTP: HTTP/1.1

# SSH
SSH: SSH-2.0
SSH: SSH-1.99
SSH: SSH-1.5

# TLS/SSL
TLS: \x16\x03\x01
TLS: \x16\x03\x02
TLS: \x16\x03\x03

# DNS (check for standard DNS header patterns)
DNS: \x00\x00\x01\x00\x00

# SIP
SIP: SIP/2.0
SIP: INVITE 
SIP: BYE 
SIP: REGISTER 
SIP: OPTIONS sip:
SIP: SUBSCRIBE 

# FTP
FTP: 220 
FTP: USER 
FTP: PASS 
FTP: 230 User
FTP: FTP

# SMTP
SMTP: 220 
SMTP: EHLO 
SMTP: HELO 
SMTP: MAIL FROM:
SMTP: RCPT TO:

# QUIC
QUIC: Q050
QUIC: Q046
QUIC: Q043
