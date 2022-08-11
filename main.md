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

%%%

.# Abstract

This document defines how Bluetooth Low Energy (BLE) can be used to request presentation of a verifiable credential. It uses request and response syntax defined in [OpenID4VP] specification.

{mainmatter}

# Introduction

This document enables Wallets and the Verifiers who have implemented [OpnID4VP] to be able to request and receive verifiable presentations even when one or both of the entities do not have Internet connection.

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
2. Exchanging verifiable credentials

During step 1, ephemeral keys to encrypt the session are exchanged. 

Step 2 utilizes request and response syntax defined in [OpenID4VP] specification. Response type `vp_token` MUST be used to obtain the VP Token in Authorization Response.

# Protocol Flow

~~~ ascii-art
+----------+                                         +----------------+
|          |                                         |                |
|          |<---- (1) Connection setup request ------|                |
|          |          using QR code                  |                |
|          |                                         |                |
|          |----- (2) OpenID4VP Request over BLE --->|                |
|          |                                         |                |
|          |       +----------+                      |                |
|          |       |          |                      |                |
|          |       | End-User |                      |                |
| Verifier |       |          |<-- AuthN & AuthZ --->|     Wallet     |
|          |       |          |                      |                |
|          |       +----------+                      |                |
|          |                                         |                |
|          |<---- (3) OpenID4VP Response over BLE ---|                |
|          |      (verifiable presentation)          |                |
|          |                                         |                |
+----------+                                         +----------------+
~~~
Figure: OpenID4VP over BLE Protocol Flow

ToDo: Don't think Wallet has means to interact with the User to authenticate and get consent...

# BLE Connection

Wallet and the Verifier MUST support the Central role. The Wallet MUST act as GATT client. This is called client central mode.

ToDo: rename central client mode as being less ISOy?

The UUID’s used MUST be 16-byte UUID’s that are unique for the transaction. The Peripheral device MUST broadcast the service with the UUID as received during device engagement in the advertising packet. The Central device is then able to scan for the UUID and connect to the advertised service. However, the Central device may use a different mechanisms to identify the Peripheral device.

NOTE BLE stacks in mobile devices can use scan filter and caching methods to manage congested environments and manage scan intervals for device energy consumption control. This can influence the connection time required when using UUIDs for the identification of the Peripheral device. 

NOTE Finding the correct device to connect to is purely a practical problem. Connecting to the wrong Verifier does not have security implications, since due to the security methods described in Clause 9, the Wallet and Verifier will not setup a session with the wrong Verifier. Note however, that these mechanisms do not provide complete protection against a bad actor aiming to cause a denial of service attack by advertising as a fake Verifier

## UUID for Service Definition {#service-definition}

The Verifier service MUST contain the following characteristics, since the Verifier acts as the GATT server. The service MAY contain other properties.

|Characteristic	name | UUID | Mandatory	properties |
| ---|---|---|
|State| 00000005-5026-444A-9E0E-D6F2450F3A77 | Notify |
|Client2Server| 00000006-5026-444A-9E0E-D6F2450F3A77 | Write Without Response|
|Server2Client| 00000007-5026-444A-9E0E-D6F2450F3A77| Notify|
|Ident| 00000008-5026-444A-9E0E-D6F2450F3A77| Read|

ToDo: Check if there are conventions to the UUID. Original in ISO is `00000001-A123-48CE-896B-4C76973373E6`.

Each service characteristic that has the Notify property MUST contain the Client Characteristic Configuration Descriptor, with UUID ‘0x29 0x02’ and default value of ‘0x00 0x00’. This value MUST be set to ‘0x00 0x01’ by the GATT client to get notified for the characteristic associated to this descriptor.

ToDo: make less ISOy.

## Connection State Values {#connection-state-values}

After the connection is setup the GATT client subscribes to notifications of characteristic ‘State’ and ‘Server2Client’. For performance reasons, the GATT client should request for an as high an MTU as possible. After these steps, the GATT client makes a write without response request to ‘State’ where it sets the value to 0x01. This tells the GATT server that the GATT client is ready for the transmission to start. 

The connection state is indicated by the ‘State’ characteristic. It is encoded as 1-byte binary data. Table 13 describes the different connection state values, which are communicated using write without response and notify. 

|Command| Data| Sender |Description |
|---|---|---|---|
|Start | 0x01 | GATT client | This indicates that the Verifier may/will begin transmission. |
|End | 0x02 | Wallet, Verifier | Signal to finish/terminate transaction. The Verifier MUST use this value to signal the end of data retrieval. Both the Wallet and the Verifier can use this value at any time to terminate the connection. See (#session-termination) for more information on session termination.|

## OpenID4VP Request and Response over BLE

OpenID4VP Request starts when GATT Client (Wallet) signals `Start` value to the `State` charateristic.

When the GATT server (Verifier) wants to send a message to the GATT client (Wallet), it divides the message in parts with a length of 3 bytes less than the MTU size. It then sends these parts to the GATT client using the notify command via the ‘Server2Client’ characteristic. The first byte of each part is either 0x01, which indicates more parts are coming, or 0x00, to indicate it is the last part of the message. 

When the GATT client (Wallet) wants to send a message to the GATT server (Verifier), it divides the message in parts with a length of 3 bytes less than the MTU size. It then sends these parts to the GATT server using the write without response command via the ‘Client2Server’ characteristic. The first byte of each part is either 0x01, which indicates more messages are coming, or 0x00, to indicate it is the last part of the message. 

The sequence of messages MUST be repeated as long as necessary to finish sending Authorization Request and Response.

```plantuml
participant "GATT server (Verifier)" as V
participant "GATT client (Wallet)" as W
autoactivate off
hide footbox

Note over V: GATT Verifier (Verifier) sends a message
group loop
V ->W: write without response to Server2Client characteristic\nwith partial message data (prepend 0x01).
end
V->W: notify from Server2Client characteristic\nwith partial message data (prepend 0x00).

Note over W: GATT client (Wallet) sends a message
group loop
W -> V:write without response to Client2Server characteristic\nwith partial message data (prepend 0x01).
end
W->V: notify from Client2Server characteristic\nwith partial message data (prepend 0x00).
```

## Connection closure 

After data retrieval, the GATT client unsubscribes from both the ‘State’ and ‘Server2Client’ characteristics. 

## Connection re-establishment 

In case of a lost connection before the ‘state’ characteristic has been set to a value of 0x01 (e.g. the transmission has not yet started), the Wallet and Verifier should terminate their current BLE session and try to reconnect according to (#setup-request). In case of a lost connection after the 'state' characteristic has been set to value 0x01 (e.g. the transmission of data has started), a connection MUST NOT be re-established and a completely new Wallet transaction MUST be initiated if required.

## Session Termination {#session-termination}

The session MUST be terminated if at least one of the following conditions occur: 
* After a time-out of no activity occurs. 
* If the Wallet does not want to receive any further requests. 
* If the Verifier does not want to send any further requests. 

A Wallet or Verifier has two options to send the termination message: 
* To send the status code for session termination. 
* To send the "End" command defined in (#connection-state-values)

If the intent to terminate the session is received, the Wallet and Verifier MUST perform at least the following actions: 
* Destruction of session keys and related ephemeral key material 
* Closure of the communication channel used for data retrieval.

ToDo: Clean-up the language so that less ISOy.

# Requests

## Connection Setup Request {#setup-request}

The Wallet MUST display to the Verifier a QR code the contains base64url-encoded Connection Setup Request with the following parameters:

* `connection_setup_encrypted_request_alg`
    * REQUIRED. JWE [RFC7516] alg algorithm JWA [RFC7518] to encrypt Connection Setup Request. MUST use identifiers defined in [JSON Web Signature and Encryption Algorithms Registry](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms) in IANA. Both Wallet and the Verifier MUST support ES256 (ECDSA using P-256 and SHA-256).
* `connection_setup_encrypted_request_enc`
    * REQUIRED. JWE [RFC7516] enc algorithm JWA [RFC7518] to encrypt Connection Setup Request. MUST use identifiers defined in [JSON Web Signature and Encryption Algorithms Registry](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms) in IANA.
* `ephemeral_verifier_pub_key`
    * REQUIRED. A JSON object that is an ephemeral public key generated by the Wallet for session encryption. The key is a bare key in JWK [RFC7517] format (not an X.509 certificate value).
* `data_presentation_method`
    * REQUIRED. MUST be `ble`.
* `uuid_client_central_mode`
    * REQUIRED. UUID for the client central mode? MUST be encoded using variant 1 (‘10x’b) as specified in [RFC4122]. 

ToDo: passing `ephemeral_Verifier_pub_key` in JSON in the QR code might be too big?
ToDo: check what cipher suites define.
ToDo: `data_presentation_method` as placeholders for how the Verifier know this is the request for the OpenID4VP over BLE. can be replaced with <Custom URL scheme>://ble? structure. (assumes that the verifier is always a native app...)
ToDo: omitted parameter - version of the specification supported
ToDo: Can `data_presentation_method` be `HTTP` if the wallet wants to fallback to usual OpenID4VP?
ToDo: clarify that signing connection setup is not defined?
ToDo: Mandating SHA256 for now.
ToDo: The contents of the Alternative Carrier Record and Carrier Configuration Record(s) MUST comply with    Clause 8.3.3.1.1.2.

Below is a non-normative example of a Connection Setup request (with line wraps within values for display purposes only):

```
  openid://ble?
    connection_setup_encrypted_request_alg=SHA256
    &connection_setup_encrypted_request_enc=A128CBC-HS256
    &ephemeral_verifier_pub_key=...
    &data_presentation_method=ble
    &uuid_client_central_mode=...
```

How the Connection Setup Request reaches a Wallet of a user's choice that capable of handling the request is out of scope of this specification(i.e. the usage of the Custom URL Schemes, Claimed URLs, etc.). See Chapter 7 of [SIOPv2] for some recommendations.

Connection Setup Request MUST be base64url-encoded without padding as defined in [RFC4648], as path.

ToDo: check what ", as path" means.

## Checking if Connected to a Correct Entity (ISO copy paste currently)

To ensure that the Wallet is connected to the correct Client, the Wallet may verify the Ident characteristic as described in (#service-definition). The Ident characteristic value shall be calculated using the following procedure:

Use HKDF as defined in RFC 5869 with the following parameters:

— Hash: SHA-256,
— IKM: EdeviceKeyBytes (see 9.1.1.4),
— salt: (no salt value is provided),
— info:”BLEIdent” (encoded as a UTF-8 string),
— L: 16 octets.

If the Ident characteristic received from the Client does not match the expected value, the Wallet shall terminate the connection.

NOTE 3 The purpose of the Ident characteristic is only to verify whether the Wallet is connected to the correct Client before setting starting data retrieval. If the Wallet is connected to the wrong Client, session establishment will fail. Connecting and disconnecting to an Client takes a relatively large amount of time and it is therefore fastest to implement methods to identify the correct Client to connect to and not to rely purely on the Ident characteristic to identify the correct Client.

## OpenID4VP Request

### Request Parameter Extension

This document extends [OpenID4VP] specification with the following parameters:

`ephemeral_Verifier_pub_key`: REQUIRED. A JSON object that is an ephemeral public key generated by the Verifier for session encryption. The key is a bare key in JWK [RFC7517] format (not an X.509 certificate value).

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
- no support for the Peropheral role.
- did not define a custom URL scheme that can open any compliant wallet.

{backmatter}