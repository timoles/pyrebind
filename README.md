pyrebind
========

pyrebind is a very simple DNS server written in Python for testing software against DNS rebinding vulnerabilities. The server responds to queries by randomly selecting one of the IP addresses specified in the requested domain name and returning it as the answer with the lowest possible TTL=1.

https://en.wikipedia.org/wiki/DNS_rebinding

DNS request

```bash
dig @127.0.0.1 -p 53 test.de +short # 
```

Here is how it looks in action:

```bash
sudo python pyrebind.py   
[*] Binding DNS server on Port: 53
[+] 2019-03-09 20:39:33.519562 ->  Got request from victim server. IP: 127.0.0.1
[*]     test.de. -> 127.0.0.1  
[*] Got request from IP: 10.10.10.10
[*]     test.de. -> 192.168.10.0
```

Constraints
-----------

This implementation aims to be as simple as possible and therefore it supports only standard `IN A` queries - other are simply ignored. Also keep in mind it requires high privileges to bind port 53/udp and lacks proper error handling. With that said, it is highly recommended to not use it for anything important.

----

# TODO 

* change readme

* argsparse
