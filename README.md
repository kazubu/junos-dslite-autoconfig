# DS-Lite Auto Provisioning

This program is a sample implementation of [IPv6マイグレーション技術の国内標準プロビジョニング方式 【第1.1版】](https://github.com/v6pc/v6mig-prov/blob/1.1/spec.md) for Junos router.

## Usage

 - Execute `pip install -r requirements.txt` to install required library.
 - Run `./build.sh` to generate `dslite_autoconfig.py`
 - Copy `dslite_autoconfig.py` to `/var/db/scripts/event/`
 - Change script permission to 755 (`chmod 755 /var/db/scripts/event/dslite_autoconfig.py`).

### Static address configuration for NGN facing interface
 - Load following configuration to Junos box(need to change NTT_EAST, ge-0/0/0.0, and USERNAME to appropriate value).

```
set event-options generate-event dslite_update time-interval 1800
set event-options policy update-dslite-config events dslite_update
set event-options policy update-dslite-config then event-script dslite_autoconfig.py arguments -area NTT_EAST
set event-options policy update-dslite-config then event-script dslite_autoconfig.py arguments -external-interface ge-0/0/0.0
set event-options event-script file dslite_autoconfig.py python-script-user USERNAME
```

 - Other required configuration(need to change interface name and addresses to appropriate value):
```
set interfaces ge-0/0/0.0 unit 0 family inet6 address 2001:db8::2/64
set routing-options rib inet6.0 static route ::/0 next-hop 2001:db8::1
set routing-options static route 0/0 next-hop ip-0/0/0.0
```

### Dynamic address configuration using RA for NGN facing interface
 - Load following configuration to Junos box(need to change ge-0/0/0.0 and USERNAME to appropriate value).

```
set event-options generate-event dslite_update time-interval 1800
set event-options policy update-dslite-config events dslite_update
set event-options policy update-dslite-config then event-script dslite_autoconfig.py arguments -dns-from-dhcpv6 true
set event-options policy update-dslite-config then event-script dslite_autoconfig.py arguments -external-interface ge-0/0/0.0
set event-options event-script file dslite_autoconfig.py python-script-user USERNAME
```

 - Other required configuration(need to change interface name to appropriate value):
```
set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-type autoconfig
set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-ia-type ia-na
set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-identifier duid-type duid-ll
set protocols router-advertisement interface ge-0/0/0.0 default-lifetime 0
set routing-options static route 0/0 next-hop ip-0/0/0.0
```


 - This program is possible to use as library to obtain AFTR address. `get_aftr.py` is an example.

## Verified VNEs
 - Internet Multifeed transix (NTT East, Flet's Next, 2022/02)
   - AFTR address is an IPv6 address.
 - AsahiNet v6コネクト (NTT East, Flet's Cross, 2022/02)
   - AFTR address is FQDN. Returns 1 AAAA record.

## Caveats
 - Covers only vendorid, product, version and capability parameters. Persistent token and authentication is not implemented.
 - Currently, SRX doesn't support IPIP6 tunnel. This script works only on MX series router.
 - Currently, MX series router doesn't support DHCPv6 client with autoconfig(RA) mode(statefull ia-pd only).

## Acknowledgement
It contains pieces of code from the following softwares:

 -  [Original DNS Client Implementation(vmartyanov/dns)](https://github.com/vmartyanov/dns) by Vladimir Martyanov
