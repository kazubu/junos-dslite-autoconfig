# DS-Lite Auto Provisioning

This program is a sample implementation of [IPv6マイグレーション技術の国内標準プロビジョニング方式 【第1.1版】](https://github.com/v6pc/v6mig-prov/blob/1.1/spec.md).

## Caveats
 - Covers only vendorid, product, version and capability parameters. Persistent token and authentication is not implemented.
 - TLS certificate validation is disabled.

## Acknowledgement
It contains pieces of code from the following softwares:

 -  [Original DNS Client Implementation(vmartyanov/dns)](https://github.com/vmartyanov/dns) by Vladimir Martyanov
