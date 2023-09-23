$ORIGIN .
$TTL 259200	; 3 days
example.com		IN SOA	ns.example.com. hostmaster.example.com. (
				2020122801 ; serial
				28800      ; refresh (8 hours)
				7200       ; retry (2 hours)
				2419200    ; expire (4 weeks)
				86400      ; minimum (1 day)
				)
			NS	ns.example.com.
$ORIGIN example.com.
$TTL 3600	; 1 hour
kdc			A	192.168.10.100
ns			A	192.168.10.101
client			A	192.168.10.102
