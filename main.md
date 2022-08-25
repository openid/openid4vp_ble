%%%
title = "OpenID for Verifiable Presentations over BLE"
abbrev = "opendi4vp-offline"
ipr = "none"
workgroup = "OpenID Connect"
keyword = ["security", "openid", "ssi"]

[seriesInfo]
name = "Internet-Draft"
value = "openid-for-verifiable-presentations-offline-1_0-01"
status = "standard"

[[author]]
initials="K."
surname="Yasuda"
fullname="Kristina Yasuda"
organization="Microsoft"
    [author.address]
    email = "kristina.yasuda@microsoft.com"

[[author]]
initials="T."
surname="Lodderstedt"
fullname="Torsten Lodderstedt"
organization="yes.com"
    [author.address]
    email = "torsten@lodderstedt.net"

[[author]]
initials="K."
surname="Nakamura"
fullname="Kenichi Nakamura"
organization="Panasonic"
    [author.address]
    email = "nakamura.kenken@jp.panasonic.com"

[[author]]
initials="G."
fullname="Sasikumar"
organization="MOSIP"
    [author.address]
    email = "sasi@mosip.io"

[[author]]
initials="N."
fullname="Ramesh"
organization="MOSIP"
    [author.address]
    email = "ramesh@mosip.io"

%%%

.# Abstract

This document defines how Bluetooth Low Energy (BLE) can be used to request presentation of a verifiable credential. It uses request and response syntax defined in [OpenID4VP] specification.

{mainmatter}

# Introduction

This document enables Wallets and the Verifiers who have implemented [OpenID4VP] to be able to request and receive verifiable presentations even when one or both of the entities do not have Internet connection.

The document defines how Bluetooth Low Energy (BLE) can be used to request presentation of a verifiable credential.It uses request and response syntax defined in [OpenID4VP] specification.

# Terms and Definitions

verifiable credential
wallet
the Verifier

//WIP

ToDo: "Connection" or "Session"?

# Use Cases

## Use Case when only wallet is offline

## Use Case when only the Verifier is offline

## Use Case when both wallet and the Verifier are offline

# Scope

//WIP

# Overview

Wallet and the Verifier MUST implement BLE according to the [Bluetooth Core Specification 4.0](https://www.bluetooth.com/specifications/specs/core-specification-4-0/). 

Wallet and the Verifier MUST support LE Data Packet Length Extension.

ToDo: For the wallet, mDL mandates 4.0, and recommends 4.2. and LE data Pathet Length Extension. For the reader, 4.2 and LE Data Packet Length Extension is mandated and 5.0 and LE 2M PHY is recommended.

The protocol consists of the following two steps:

1. Establishing a connection
2. Verifying the parties
3. Exchanging verifiable credentials
4. Finalizing the exchange

During step 1, ephemeral keys to encrypt the session are exchanged. 



Step 2 utilizes request and response syntax defined in [OpenID4VP] specification. Response type `vp_token` MUST be used to obtain the VP Token in Authorization Response.

# Protocol Flow

## Simple Flow 

Verifier opens his app
Moves to the accepting OpenID4VP mode.
Verifier app starts BLE advertisement. 
The same can be made as a request QR code.
Wallet scans the BLE layer and filters the OpenID4VP automatically (in case it found only one) or a QR code is scanned.
Wallet connects.
Negotiates Security and details to be sent.
Sends VC


~~~ ascii-art
+-------------+                                         +----------------+
|             |                                         |                |
|             |<---- (1) Connection setup request ------|                |
|             |          using QR code or discovery     |                |
|             |                                         |                |
|             |----- (2) OpenID4VP Request over BLE --->|                |
|             |          verify the requester           |                |
|             |       +----------+                      |                |
|             |       |          |                      |                |
|             |       | End-User |                      |                |
| Verifier    |       |          |<-- AuthN & AuthZ --->|     Wallet     |
| (Peripheral |       |          |                      | (Central GAP   |
|  GAP Role,  |       +----------+                      |  Role,         |
|  Server)    |                                         |  Client)       |
|             |<---- (3) OpenID4VP Response over BLE ---|                |
|             |      (verifiable presentation)          |                |
|             |                                         |                |
|             |----- (4) Finalize the exchange -------->|                |
+-------------+          & Close connection             +----------------+
~~~
Figure: OpenID4VP over BLE Protocol Flow

ToDo: Don't think Wallet has means to interact with the User to authenticate and get consent...

## 

BLE Advertisement Packet structure

PDU:
    Header:
        PDU type: ADV_IND
        Tx Address: Random
        Rx Address: Random
    Payload: (37 bytes)
        Adv Address: Random address
        Adv Data: (32 byte)
            Adv Type: Complete Local Name
            flag: "LE General Discoverable Mode", "BR/EDR Not Supported"
            Data: OPENID4VP_8520f0098930a754748b7ddcb43ef75a (5 bytes + 16 bytes ) Half of the random X25519 public key


Use the same structure with the remainng half of the key (0dbf3a0d26381af4eba4a98eaa9b4e6a) during scan response.



QR Code Dynamic - OPENID4VP, public key (ED25519 key)
BLE Advertisement -  OPENID4VP, first 16 byte of ED25519 public key (max available size 29 byte), Response to the scan we will send the remaining 16 byte of ED25519, 

+-----------+                       +-----------+
|           |-----PDU ADV_IND------>|           |
|  Adv      |<----SCAN_REQ----------| Scanner   |
|           |-----SCAN_RESP-------->|           |
+-----------+                       +-----------+


# Connection Flow

Wallet MUST support the Central role and is responsible to connect to the verifier. The Verifier MUST support the Peripheral Role and should advertise its details. As the advertisement completes the Wallet now has the peripheral details and X25519 keys of the verifier. The sequence of flow is as described.

Step 1: Wallet generates a X25519 keys of its own and combines to create a DHE secret key very similar to the sodium NACL (May be we can choose signal protocol?). 
Step 2: Identify request is made and wallet submits its key to the verifier (plain text).
Step 3: Wallet reads the request from the Verifier . (Encrypted with the secret key)
Step 4: Wallet shows the requrest to the user to get his consent/permission.  
Step 5: Upon consent Wallet does the necessary authentication if requested and then Submits the VC
Step 6: The verifier accepts the VC if they could decrypt and validate the signature.
Step 7: Both the wallet and client records in their respective audit logs.

## UUID for Service Definition {#service-definition}

The Verifier service MUST contain the following characteristics, since the Verifier acts as the server.

TODO: Can we plan to register our service with Bluetooth SIG? This will allow us to have 

Verifier Service - UUID 00000001-5026-444A-9E0E-D6F2450F3A77 

|Characteristic name | UUID                                 | Mandatory properties  | Description         |
|--------------------|--------------------------------------|-----------------------|---------------------|
|Request             | 00000005-5026-444A-9E0E-D6F2450F3A77 | Read                  | Get the request JSON|
|Identify            | 00000006-5026-444A-9E0E-D6F2450F3A77 | Write                 | Wallet identifies   |
|Submit VC           | 00000007-5026-444A-9E0E-D6F2450F3A77 | Write                 | Submit the VC       |
+--------------------+--------------------------------------+-----------------------+---------------------+

ToDo: Check if there are conventions to the UUID. Original in ISO is `00000001-A123-48CE-896B-4C76973373E6`.

## Connection closure 

After data retrieval, the GATT client unsubscribes from all characteristics. 

## Connection re-establishment 

In case of a lost connection a full flow is conducted again.

## Session Termination {#session-termination}

The session MUST be terminated if at least one of the following conditions occur: 
* After a time-out of no activity occurs. 
* If the Wallet does not want to receive any further requests. 
* If the Verifier does not want to send any further requests. 

Termination is as per the default BLE write. 

In case of a termination, the Wallet and Verifier MUST perform at least the following actions: 
* Destruction of session keys and related ephemeral key material 
* Closure of the communication channel used for data retrieval.

[SASI] TODO: Should we support multiple encryption type or pick the signal route?
# Encryption

## Overview

1. The Wallet generates an ephemeral key pair and in the Connection Setup Request sends to the Verifier the ephemeral public key and the identifier of the algorithm.
2. The Verifier generates an ephemeral key pair using the algorithm received in the Connection Setup Request. 
3. The Verifier derives a session key using the Wallet's public key received in the Connection Setup Request, and encrypts OpenID4VP Request using it.
4. The Verifier sends an encrypted OpenID4VP Request to the Verifier that contains Verifier's ephemeral public key.
5. The Wallet derives a session key using the Verifier's public key received in the OpenID4VP Request, and encrypts OpenID4VP Response using it.
6. The Verifier decrypts OpenID4VP Response using the session key computed in step 3.

Note that Connection Setup Request itself MUST NOT be encrypted.

## Session Key Computation

To calculate the session keys, the Wallet and the Verifier MUST perform ECKA-DH (Elliptic Curve Key Agreement Algorithm – Diffie-Hellman) as defined in BSI TR-03111. The Zab output defined in BSI TR-03111 MUST be used to derive 2 keys. 

The Verifier MUST derive session key using HKDF as defined in [RFC5869] with the following parameters: 

* Hash: SHA-256 
* IKM: Zab 
* salt: SHA-256
* info: “SKVerifier” (encoded as ASCII string) 
* L: 32 octets 

The Wallet MUST derive session key using HKDF as defined in [RFC5869] with the following parameters: 

* Hash: SHA-256 
* IKM: Zab 
* salt: SHA-256
* info: “SKWallet” (encoded as ASCII string) 
* L: 32 octets 

For encryption AES-256-GCM (GCM: Galois Counter Mode) as defined in NIST SP 800-38D MUST be used. 

The IV (Initialization Vector defined in NIST SP 800-38D) used for encryption MUST have the default length of 12 bytes for GCM, as specified in NIST SP 800-38D. The IV MUST be the concatenation of the identifier and the message counter (identifier || message counter). The identifier MUST be an 8-byte value. 

The Verifier MUST use the following identifier: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00. 
The Wallet MUST use the following identifier: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01.

The Wallet and Verifier MUST keep a separate message counter for each session key. The message counter value MUST be a 4-byte big-endian unsigned integer. For the first encryption with a session key, the message counter MUST be set to 1. Before each following encryption with the same key, the message counter value MUST be increased by 1. A message counter value MUST never be reused in any future encryption using the same key. The AAD (Additional Authenticated Data defined in NIST SP 800-38D) used as input for the GCM function MUST be an empty string. The plaintext used as input for the GCM function MUST be Wallet request or Wallet response. The value of the data element in the session establishment and session data messages as defined in 9.1.1.4 MUST be the concatenation of the ciphertext and all 16 bytes of the authentication tag (ciphertext || authentication tag).

ToDo: Clean-up the language so that less ISOy.

## OpenID4VP Request Encryption

To encrypt OpenID4VP Response, [RFC9191](https://datatracker.ietf.org/doc/html/rfc9101) MUST be used. JAR defines how Authorization Request parameters cab be conveyed as a JWT, which can be encrypted as a whole.

## OpenID4VP Response Encryption

To encrypt OpenID4VP Response, [JARM](https://openid.net//specs/openid-financial-api-jarm-wd-01.html) MUST be used. JARM defines how Authorization Response parameters cab be conveyed in a JWT, which can be encrypted as a whole.

For the response_type "vp_token" the JWT contains the response parameters as defined in [OpenID4VP]:

* `vp_token` - the VP token
* `presentation_submission` - contains information where to find a requested verifiable credential.

The following example shows the claims of the JWT for a successful `vp_token` Authorization Response:

{
   "vp_token":"<base64url-encoded VP Token>",
   "presentation_submission":"<base64url-encoded `presentation_submission`>"
}

# Security Considerations

## Session Information

Both wallet and the Verifier MUST remove all the information about the session after its termination.

## Ensuring the Wallet is Connected to teh correct Verifier

To ensure that the Wallet is connected to the correct Verifier. The Wallet may verify the Ident characteristic as described in Clause 8.3.3.1.4. The Ident characteristic value MUST be calculated using the following procedure: 

Use HKDF an defined in RFC 5869 with the following parameters: 
* Hash: SHA-256 
* IKM: EdeviceKeyBytes (see Clause 9.1.1.4) 
* salt: (no salt value is provided) 
* info:”BLEIdent” (encoded as ASCII string) 
* L: 16 octets 
If the Ident characteristic received from the Verifier does not match the expected value, the Wallet MUST disconnect from the Verifier. 

NOTE The purpose of the Ident characteristic is only to verify whether the Wallet is connected to the correct Verifier before setting starting OpenID4VP Request. If the Wallet is connected to the wrong Verifier, session establishment will fail. Connecting and disconnecting to an Verifier takes a relatively large amount of time and it is therefore fastest to implement methods to identify the correct Verifier to connect to and not to rely purely on the Ident characteristic to identify the correct Verifier. 

ToDo: Fix the language to be less ISOy.

# Security Considerations

How to secure what happens before what is defined in this protocol.

# Discussion points
 
- not requiring nor recommending BLE secure connections.

{backmatter}
