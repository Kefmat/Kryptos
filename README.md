# Project: Kryptos
**Secure Command & Control Middleware**

Kryptos er et spesialisert sikkerhetslag for kritiske infrastruktursystemer. Mens tradisjonelle UDP-strømmer sender data i klartekst, sørger Kryptos for at hver datapakke er både uleselig for uvedkommende og umulig å manipulere.

### Trusselmodeller vi løser:
1. **Eavesdropping:** AES-256 kryptering hindrer innsyn i telemetri.
2. **Command Injection:** Kun de med riktig HMAC-nøkkel kan sende gyldige kommandoer.
3. **Replay Attacks:** Integrert nonce-validering (under utvikling) sikrer at gamle pakker ikke kan brukes på nytt.

### Teknisk Stack:
- Java Cryptography Architecture (JCA)
- AES/CBC/PKCS5Padding
- HMAC-SHA256 for pakke-integritet