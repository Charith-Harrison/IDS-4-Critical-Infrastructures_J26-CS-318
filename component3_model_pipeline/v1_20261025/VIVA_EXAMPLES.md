# Worked examples from training data only

These paired cases have identical COMPLETE current ADUs, including TID. Their labels differ because the preceding observable history differs. They were selected after modelling for explanation, not used to select final examples or tune models. IDs/anchors are evidence pointers and never predictors.

## command: normal

Event `MX084-20261025T063001Z-dfeac789:e2388`. Current ADU `00050000000601050001ff00`, PDU `050001ff00`. Verified label `normal`. Earlier observed mode `1.0`; earlier acknowledged setpoint `None`; current readback minus anchor `None`.

Mode anchor `MX084-20261025T063001Z-dfeac789:e2383`, setpoint anchor `None`, earlier paired request `None`. Find those event IDs in the same accepted ledger and use verified-label frame/file references to show the source PCAP.

## command: injection

Event `MX001-20261025T050857Z-878e257e:e790`. Current ADU `00050000000601050001ff00`, PDU `050001ff00`. Verified label `command_injection`. Earlier observed mode `0.0`; earlier acknowledged setpoint `None`; current readback minus anchor `None`.

Mode anchor `MX001-20261025T050857Z-878e257e:e787`, setpoint anchor `None`, earlier paired request `None`. Find those event IDs in the same accepted ledger and use verified-label frame/file references to show the source PCAP.

## response: normal

Event `MX001-20261025T050857Z-878e257e:e1519`. Current ADU `0005000000050103020039`, PDU `03020039`. Verified label `normal`. Earlier observed mode `None`; earlier acknowledged setpoint `57.0`; current readback minus anchor `0.0`.

Mode anchor `None`, setpoint anchor `MX001-20261025T050857Z-878e257e:e1515`, earlier paired request `MX001-20261025T050857Z-878e257e:e1518`. Find those event IDs in the same accepted ledger and use verified-label frame/file references to show the source PCAP.

## response: injection

Event `MX001-20261025T050857Z-878e257e:e31`. Current ADU `0005000000050103020039`, PDU `03020039`. Verified label `response_injection`. Earlier observed mode `None`; earlier acknowledged setpoint `22.0`; current readback minus anchor `35.0`.

Mode anchor `None`, setpoint anchor `MX001-20261025T050857Z-878e257e:e27`, earlier paired request `MX001-20261025T050857Z-878e257e:e30`. Find those event IDs in the same accepted ledger and use verified-label frame/file references to show the source PCAP.

Explain it as two identical-looking messages: permission needs the earlier mode observation; readback correctness needs the earlier successful write and acknowledgement. The current reply itself has no register address. Missing that trustworthy earlier evidence means abstain. The rules directly express these relationships; the RF is a learned approximation, not proof of malicious intent outside this policy.
