# For Study

Devloped on Ubuntu-24.04.02

Use PCAP API, gcc

Sniff my vm machine's web browser http

`http_tcp_sniff.c` and `myheader.h` must be in the same directory


```

`gcc -o http_tcp_sniff http_tcp_sniff.c -lpcap`

`./wireshark`

`./http_tcp_sniff`
```

---

## Function

1. Get Packet
2. Print Ethernet Header's src/dst mac
3. Print IP Header's src/dst ip
4. Print TCP Header's src/dst port
5. Print HTTP Message
