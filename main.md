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

# Limitation

We need to be considerate of the following limitations in BLE stack 4.2

1. Advertisement
    * The advertisement message can contain only a max of 29 bytes.
    * The advertisement scan request can not have any custom data.
    * The scan response can have custom data.  
2. Timing
    * BLE Scanning and advertising are discrete events, so not every advertisement is received ```(max ~30 sec)```
3. Throughput
    * Default MTU size is 23 bytes and max is 512 bytes
    * 14 bytes are overhead cost per packet (MTU).
    * 0.226 ~ 0.301 Mbps (Mega bits per second). So data rate of ~0.10 Mbps




# Protocol Flow Overview

Below is the diagram that illustrates protocol flow:

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
| Verifier    |       |          |<- (3) AuthN & AuthZ->|     Wallet     |
| (Peripheral |       |          |                      | (Central GAP   |
|  GAP Role,  |       +----------+                      |  Role,         |
|  Server)    |                                         |  Client)       |
|             |<---- (4) OpenID4VP Response over BLE ---|                |
|             |      (verifiable presentation)          |                |
|             |                                         |                |
|             |----- (5) Finalize the exchange -------->|                |
+-------------+          & Close connection             +----------------+
~~~
Figure: OpenID4VP over BLE Protocol Flow

1. Verifier and the Wallet establish the connection. This specification defines two mechanisms to do so: QR code displayed by the Verifier and BLE Advertisement initiated by the Verifier.
2. Wallet obtains Presentation Request from the Verifier.
3. Wallet authenticates the user and obtains consent to share Credential(s) with the Verifier.
4. Wallet sends Presentation Response to the Verifier with Verifiable Presntation(s).
5. Verifier and the Wallet close connection.

# Connection Set up {#connection-set-up}

First, Verifier and the Wallet need to establish the connection. This specification defines two mechanisms to do so: QR code displayed by the Verifier and BLE Advertisement initiated by the Verifier.

## Estabilishing Connection using BLE Advertisement {#connection-ble}

This section describes how Verifier and the Wallet can establish connection by Verifier initiating BLE Advertisement. This mechanism can be used by the Verifiers when the use-case does not allow the End-Users to scan a QR code displayed on the Verifier's device, for example to ensure the safety of the Verifier.

(1) Verifier opens it's native application
(2) Verifiers starts the mode that accepts OpenID4VP.
(3) Verifier app starts BLE advertisement.
(4) Wallet scans the BLE layer and filters the OpenID4VP automatically (in case it found only one)
(5) Wallet connects to the Verifier.
(6) Wallet negotiates Security and sends details.

BLE Advertisement Packet structure MUST be the following:

```
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
```

Verifier advertises half of the public key in the original BLE Advertisement Packet. The remainng half of the key (0dbf3a0d26381af4eba4a98eaa9b4e6a) is being sent during the scan response.

BLE Advertisement -  OPENID4VP, first 16 byte of ED25519 public key (max available size 29 byte), Response to the scan we will send the remaining 16 byte of ED25519, 

+------------+                       +-----------+
|            |-----PDU ADV_IND------>|           |
| Advertiser |<----SCAN_REQ----------| Scanner   |
| (Verifier) |-----SCAN_RESP-------->| (Wallet)  |
|            |                       |           |
+------------+                       +-----------+

ToDo: Need to explain this diagram better.

## Estabilishing Connection using QR Code

This section describes how Verifier and the Wallet can establish connection by Verifier displaying a QR Code scanned using the Wallet.

(1) Verifier opens it's native application
(2) Verifiers displays a QR Code
(3) Wallet scans the QR Code.
(4) Wallet connects to the Verifier.
(5) Wallet negotiates Security and sends details.

QR code MUST contain the same structure as defined in (#connection-ble), except that when the QR Code is used to establish connection, entire public key (ED25519 key) is encoded in the QR code.

How the Connection Setup Request reaches a Wallet of a user's choice that capable of handling the request is out of scope of this specification(i.e. the usage of the Custom URL Schemes, Claimed URLs, etc.). The most certain way for a QR code to reach a target Wallet is to use a camera fature in a Wallet Application itself to scan a QR code.

# Data Exchange Flow

This section describes how the Wallet obtains Presentation Request from the Verifier, and how the Wallet sends Presentation Response to the Verifier after authenticating the user and obtaining consent to share Credential(s) with the Verifier.

ToDo: Assume we want to support both sending only VC and VC in a VP?

Wallet MUST support the Central role and is responsible for connectting to the Verifier. The Verifier MUST support the Peripheral Role and should advertise its details. After the connection is established, the Wallet has the peripheral details and X25519 keys of the verifier. The sequence of flow is as described.

Step 1: Wallet generates a X25519 keys of its own and combines to create a DHE secret key very similar to the sodium NACL (May be we can choose Signal protocol?). 
Step 2: Wallet makes identify request and submits its keys to the verifier in plain text.
Step 3: Wallet reads the Presentation request from the Verifier. (Encrypted with the secret key)
Step 4: Wallet authenticates the User and obtains consent
Step 5: Wallet submits the VC to the Verifier.
Step 6: The verifier accepts the VC if they could decrypt and validate the signature.
Step 7: Both the wallet and client records in their respective audit logs.

ToDo: Are we limiting signature suites only to X25519?

## UUID for Service Definition {#service-definition}

The Verifier acts as the server and the Verifier service MUST contain the following characteristics:

Verifier Service UUID MUST be `00000001-5026-444A-9E0E-D6F2450F3A77`.

|Characteristic name | UUID                                 | Type                  | Description         |
|--------------------|--------------------------------------|-----------------------|---------------------|
|Request Size        | 00000004-5026-444A-9E0E-D6F2450F3A77 | Read                  | Get the request size|
|Request             | 00000005-5026-444A-9E0E-D6F2450F3A77 | Read                  | Get the request JSON|
|Identify            | 00000006-5026-444A-9E0E-D6F2450F3A77 | Write                 | Wallet identifies   |
|                    |                                      |                       | as chunks           |
|Content Size        | 00000007-5026-444A-9E0E-D6F2450F3A77 | Write                 | Submit the content  |
|                    |                                      |                       | size                |
|Submit VC           | 00000008-5026-444A-9E0E-D6F2450F3A77 | Write                 | VC stream as chunks |
+--------------------+--------------------------------------+-----------------------+---------------------+

TODO: Can we plan to register our service with Bluetooth SIG? This will allow us to have 

ToDo: If 'Submit VC' latency is high due to the presence of a photograph we will fall back to the style that Kritina wrote with State.

ToDo: Check if there are conventions to the UUID. Current UUID has been randomly generated.

## Identity Request

ToDo: Need to elaborate.

## Presentation Request

Presentation Request MUST include `presentation_definition` parameter as defined in Section  of [OpenID4VP].

`response_type`, `client_id`, `redirect_uri` parameters MUST NOT be present in the Presentation Request.

ToDo: Do we want nonce to be included? I believe we do.

## Presentation Response

Presentation Response MUST include `presentation_submission` and `vp_token` parameters as defined in Section 6 of [OpenID4VP].

{
    "presentation_submission": {

    },
    "vp_token": [
        {
            VP1
        },
        {
            VP2
        }
    ] 
}

## Stream Write Packet Structure

Using the 'Content Size' characteristics the wallet sets the size. Once we receive the confirmation about the write we start the 'Submit VC' as a stream. 'Submit VC' is called multiple times until all the data is sent.

__NOTE__: Limit the total size to ```~4kb``` for better performance while the protocol can handle larger. In case the Request does not match Size then its assumed its corrupted and the same procedure is repeated again.

Clarify the error handing rationale

## Stream Read Packet Structure

The ```Request Size``` is first called to get the actual size of the request. Once the size of the request is obtained the ```Request``` characteristics is called to get the actual data. The characteristics is called repeatedly until all the requested data is received.

To read the complete Characteristic Value an ATT_READ_REQ PDU should be used for the first part of the value and ATT_READ_BLOB_REQ PDUs shall used for the rest. The Value Offset parameter of each ATT_READ_BLOB_REQ PDU shall be set to the offset of the next octet within the Characteristic Value that has yet to be read. The ATT_READ_BLOB_REQ PDU is repeated until the ATT_READ_BLOB_RSP PDU’s Part Attribute Value parameter is shorter than (ATT_MTU – 1).

__NOTE__: In case the Request does not match Size then its assumed its corrupted and the same procedure is repeated again.

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

[SASI] TODO: Should we support multiple encryption type or pick the single encryption route?

# Encryption

## Overview

1. The Wallet obtains Verifier's ephemeral key pair in the Connection Setup Request from BLE Advertisement or a QR Code.
2. The Wallet generates an ephemeral key pair. 
3. The Wallet communicates its ephemeral key pair to the Verifier in the Identity Request.
4. The Verifier derives an encryption key using the Wallet's public key received in the Idenity Request, and encrypts Presentation Request using it.
5. The Wallet derives an encryption key using the Verifier's public key received in the Connection Set Up phase, decrypts Presentation Request and encrypts Presentation Response using it.
6. The Verifier decrypts Presentation Response using the encryption key computed in step 4.

Note that Connection Setup Request itself defined in (#connection-set-up) MUST NOT be encrypted.

ToDo: no algorithm identifier since looks like we are doing only X25519?

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

For encryption AES-256-GCM (192) (GCM: Galois Counter Mode)  as defined in NIST SP 800-38D or ChaCha20 RFC 8439 MUST be used. 

ToDo: Can we do ChaCha20? Rather than AES 256 GCM? The fact that ChaCha20 is more streaming.

The IV (Initialization Vector defined in NIST SP 800-38D) used for encryption MUST have the default length of 12 bytes for GCM, as specified in NIST SP 800-38D. The IV MUST be the concatenation of the identifier and the message counter (identifier || message counter). The identifier MUST be an 8-byte value. 

The Verifier MUST use the following identifier: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00. 
The Wallet MUST use the following identifier: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01.

The Wallet and Verifier MUST keep a separate message counter for each session key. The message counter value MUST be a 4-byte big-endian unsigned integer. For the first encryption with a session key, the message counter MUST be set to 1. Before each following encryption with the same key, the message counter value MUST be increased by 1. A message counter value MUST never be reused in any future encryption using the same key. The AAD (Additional Authenticated Data defined in NIST SP 800-38D) used as input for the GCM function MUST be an empty string. The plaintext used as input for the GCM function MUST be Wallet request or Wallet response. The value of the data element in the session establishment and session data messages as defined in 9.1.1.4 MUST be the concatenation of the ciphertext and all 16 bytes of the authentication tag (ciphertext || authentication tag).

# Security Considerations

## Session Information

Both wallet and the Verifier MUST remove all the information about the session after its termination.

## Ensuring the Wallet is Connected to the correct Verifier

To ensure that the Wallet is connected to the correct Verifier. The Wallet may verify the Ident characteristic as described in Clause 8.3.3.1.4. The Ident characteristic value MUST be calculated using the following procedure: 

Use HKDF an defined in RFC 5869 with the following parameters: 
* Hash: SHA-256 
* IKM: EdeviceKeyBytes (see Clause 9.1.1.4) 
* salt: (no salt value is provided) 
* info:”BLEIdent” (encoded as ASCII string) 
* L: 16 octets 
If the Ident characteristic received from the Verifier does not match the expected value, the Wallet MUST disconnect from the Verifier. 

NOTE The purpose of the Ident characteristic is only to verify whether the Wallet is connected to the correct Verifier before setting starting OpenID4VP Request. If the Wallet is connected to the wrong Verifier, session establishment will fail. Connecting and disconnecting to an Verifier takes a relatively large amount of time and it is therefore fastest to implement methods to identify the correct Verifier to connect to and not to rely purely on the Ident characteristic to identify the correct Verifier. 


## Verifier Authentication

How does the wallet authenticate the Verifier?

## Session Binding

How does the Verifier know a particular response is tied to a particular request?

## Other

ToDo: Mention that BLE HW is inherently not secure? securing which is out of scope of this protocol?

# Discussion points
 
- not requiring nor recommending BLE secure connections.

{backmatter}
