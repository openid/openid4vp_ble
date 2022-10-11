%%%
title = "OpenID for Verifiable Presentations over BLE"
abbrev = "opendi4vp-offline"
ipr = "none"
workgroup = "OpenID Connect"
keyword = ["security", "openid", "ssi"]

[seriesInfo]
name = "Internet-Draft"
value = "openid-for-verifiable-presentations-offline-1_0-00"
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

This document defines how Bluetooth Low Energy (BLE) can be used to request presentation of a verifiable credentials. It uses request and response syntax as defined in [@!OpenID4VP].

{mainmatter}

# Introduction

This document enables Wallets and the Verifiers who have implemented [@!OpenID4VP] to request and receive verifiable presentations even if one or both of the entities do not have Internet connection by utilizing Bluetooth Low Energy (BLE). This document uses request and response syntax as defined in [@!OpenID4VP].

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

Wallet and the Verifier MUST implement BLE according to the [@!Bluetooth.4.Core] specification . 

Wallet and the Verifier MUST support LE Data Packet Length Extension. [TLT: Reference?]

ToDo: For the wallet, mDL mandates 4.0, and recommends 4.2. and LE data Pathet Length Extension. For the reader, 4.2 and LE Data Packet Length Extension is mandated and 5.0 and LE 2M PHY is recommended.

The protocol consists of the following two steps:

1. Establishing a BLE connection
2. Verifying the parties
3. Exchanging verifiable credentials
4. Finalizing the exchange

During step 1, ephemeral keys to encrypt the session are exchanged. 
Note: authentication of the parties can be implemented on the OpenID layer. 

Step 2 utilizes request and response syntax as defined in [!@OpenID4VP]. Response type `vp_token` MUST be used to obtain the VP Token in Authorization Response.
[TLT: why do we need a response type at all?]

# Limitation

We need to be considerate of the following limitations in BLE stack 4.2

1. Advertisement
    * The advertisement message can contain only a max of 29 bytes.
    * The advertisement scan request can not have any custom data.
    * The scan response can have custom data.  
2. Timing
    * BLE Scanning and advertising are discrete events, so not every advertisement is received ```(max ~30 sec)``` [TLT: what does the max 30s mean?]
3. Throughput
    * Default MTU size is 23 bytes and max is 512 bytes
    * 14 bytes are overhead cost per packet (MTU).
    * 0.226 ~ 0.301 Mbps (Mega bits per second). So data rate of ~0.10 Mbps
[TLT: don't understand why the effective rate is 1/3 of the overall throuput given max MTU is 512 Bytes (to 14 bytes overhead)?]
[TLT: should we also mention that the protocol isn't really a message exchange but rather the wallet setting and reading things?]

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

First, Verifier and the Wallet need to establish the connection. This specification defines two mechanisms to do so: BLE Advertisement initiated by the Verifier and QR code displayed by the Verifier.

## Estabilishing Connection using BLE Advertisement {#connection-ble}

This section describes how Verifier and the Wallet can establish connection by Verifier initiating BLE Advertisement. This mechanism can be used by the Verifiers when the use-case does not allow the End-Users to scan a QR code displayed on the Verifier's device, for example to ensure the safety of the Verifier.

(1) Verifier opens it's native application [TLT: why is that important (opening an app and that it is a native app)?]
(2) Verifiers starts the mode that accepts OpenID4VP.
(3) Verifier app starts BLE advertisement.
(4) Wallet scans the BLE layer and filters the OpenID4VP automatically (in case it found only one). If there are multiple verifiers the user is asked to choose. 
(5) Wallet connects to the Verifier.
(6) Wallet generates a X25519 keys of its own and combines to create a DHE secret key very similar to the sodium NACL (May be we can choose Signal protocol?). 
(7) Wallet makes identify request and submits its keys to the verifier in plain text.

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
[TLT: why doesn't the verifier just send OPENID4VP and the key in the subsequent request. That would allow the verifier to use connection specific keys even if running for a longer period (think security gate)]

Verifier advertises half of the public key in the original BLE Advertisement Packet (max available size 29 byte). The remainng half of the key (16 byte of ED25519 - example: 0dbf3a0d26381af4eba4a98eaa9b4e6a) is being sent during the scan response.

~~~ ascii-art
+------------+                       +-----------+
|            |-----PDU ADV_IND------>|           |
| Advertiser |<----SCAN_REQ----------| Scanner   |
| (Verifier) |-----SCAN_RESP-------->| (Wallet)  |
|            |                       |           |
+------------+                       +-----------+
~~~

ToDo: Need to explain this diagram better.
[TLT: I cannot map the desciption above with the diagram. How many messages are exchanged?]

## Estabilishing Connection using QR Code

This section describes how Verifier and the Wallet can establish connection by Verifier displaying a QR Code scanned using the Wallet.

(1) Verifier opens it's native application
(2) Verifiers displays a QR Code
(3) Wallet scans the QR Code.
(4) Wallet connects to the Verifier.
(6) Wallet generates a X25519 keys of its own and combines to create a DHE secret key very similar to the sodium NACL (May be we can choose Signal protocol?). 
(7) Wallet makes identify request and submits its keys to the verifier in plain text.

QR code MUST contain the same structure as defined in (#connection-ble), except that when the QR Code is used to establish connection, entire public key (ED25519 key) is encoded in the QR code.
[TLT: putting the QR code means the verifier is required to use the same key for any connection? So we loose the ability to seggragate connections to different wallets or the verifier needs to render a new QR code for every transaction. Think of the security gate again. I would prefer to setup the key in a separate step.]

How the Connection Setup Request reaches a Wallet of a user's choice that capable of handling the request is out of scope of this specification(i.e. the usage of the Custom URL Schemes, Claimed URLs, etc.). 
[TLT: I'm confused. Do you truely believe a verifier renders a URL with a custom scheme conaining a QR Code? That would mean, the wallet receives the request on the same device and then starts BLE?.}

The most certain way for a QR code to reach a target Wallet is to use a camera fature in a Wallet Application itself to scan a QR code.

# OpenID4VP Request over BLE

On the BLE layer the request is performed by the Wallet reading the Presentation request from the Verifier.

The Request is represented as a signed request object containing the parameters as defined in [!@OpenID4VP].
[TLT: is there a kind of transport encryption or is the request object encrypted?]

The request MUST contain the verifier's client id in the `iss` claim. 
The request MUST contain the wallet identifier in the `aud` claim. 
[TLT: not sure what identifier to use - aud and nonce together are intended for replay detection]

The request MUST include one of the following parameters:
* `presentation_definition` or
* `presentation_definition_uri` or
* `scope` (if that scope represents a credential presentation request or is `openid`)

The request SHOULD contain a `nonce`. 

The parameters `response_type` and `redirect_uri` MUST NOT be present in the request.

The following is a non normative example of a request before signing:

```json
{
    "iss": "s6BhdRkqt3",
    "aud": "wallet_id",
    "nonce": "n-0S6_WzA2Mj",
    "presentation_definition": {
        "id": "vp token example",
        "input_descriptors": [
            {
                "id": "id card credential",
                "format": {
                    "ldp_vc": {
                        "proof_type": [
                            "Ed25519Signature2018"
                        ]
                    }
                },
                "constraints": {
                    "fields": [
                        {
                            "path": [
                                "$.type"
                            ],
                            "filter": {
                                "type": "string",
                                "pattern": "IDCardCredential"
                            }
                        }
                    ]
                }
            }
        ]
    }
}
```

# OpenID4VP Response over BLE

On the BLE layer the response is transmitted by the Wallet submitting the presentation to the Verifier.

The response contains the parameters as defined in Section 6 of [!@OpenID4VP] in JSON encoding. 

The wallet MAY sign the request. In this case, the response is encoded as a JWT. 

[TLT: is there a kind of transport encryption or is the response object encrypted?]

ToDo: Assume we want to support both sending only VC and VC in a VP?
[TLT: why should we deviate from OpenID4VP?]

ToDo: Are we limiting signature suites only to X25519?

The following is a non normative example of a response before signing:

```json
{
    "presentation_submission": {
        "id": "Selective disclosure example presentation",
        "definition_id": "Selective disclosure example",
        "descriptor_map": [
            {
                "id": "ID Card with constraints",
                "format": "ldp_vp",
                "path": "$",
                "path_nested": {
                    "format": "ldp_vc",
                    "path": "$.verifiableCredential[0]"
                }
            }
        ]
    },
    "vp_token": [
        {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "type": [
                "VerifiablePresentation"
            ],
            "verifiableCredential": [
                {
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                    ],
                    "id": "https://example.com/credentials/1872",
                    "type": [
                        "VerifiableCredential",
                        "IDCardCredential"
                    ],
                    "issuer": {
                        "id": "did:example:issuer"
                    },
                    "issuanceDate": "2010-01-01T19:23:24Z",
                    "credentialSubject": {
                        "given_name": "Fredrik",
                        "family_name": "Str&#246;mberg",
                        "birthdate": "1949-01-22"
                    },
                    "proof": {
                        "type": "Ed25519Signature2018",
                        "created": "2021-03-19T15:30:15Z",
                        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PT8yCqVjj5ZHD0W36zsBQ47oc3El07WGPWaLUuBTOT48IgKI5HDoiFUt9idChT_Zh5s8cF_2cSRWELuD8JQdBw",
                        "proofPurpose": "assertionMethod",
                        "verificationMethod": "did:example:issuer#keys-1"
                    }
                }
            ],
            "id": "ebc6f1c2",
            "holder": "did:example:holder",
            "proof": {
                "type": "Ed25519Signature2018",
                "created": "2021-03-19T15:30:15Z",
                "challenge": "n-0S6_WzA2Mj",
                "domain": "https://client.example.org/cb",
                "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GF5Z6TamgNE8QjE3RbiDOj3n_t25_1K7NVWMUASe_OEzQV63GaKdu235MCS3hIYvepcNdQ_ZOKpGNCf0vIAoDA",
                "proofPurpose": "authentication",
                "verificationMethod": "did:example:holder#key-1"
            }
        }
    ]
}
```

# BLE Details
## UUID for Service Definition {#service-definition}

[TLT: I don't understand how this section is related to the previous sections? Should that be an appendix?]

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

ToDo: Check if there are conventions to the UUID. Original in ISO is `00000001-A123-48CE-896B-4C76973373E6`.

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

<reference anchor="OpenID4VP" target="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">
  <front>
    <title>OpenID for Verifiable Presentations</title>
    <author initials="O." surname="Terbu" fullname="Oliver Terbu">
      <organization>ConsenSys Mesh</organization>
    </author>
    <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
      <organization>yes.com</organization>
    </author>
    <author initials="K." surname="Yasuda" fullname="Kristina Yasuda">
      <organization>Microsoft</organization>
    </author>
    <author initials="A." surname="Lemmon" fullname="Adam Lemmon">
      <organization>Convergence.tech</organization>
    </author>
    <author initials="T." surname="Looker" fullname="Tobias Looker">
      <organization>Mattr</organization>
    </author>
    <date day="20" month="May" year="2021"/>
  </front>
</reference>

<reference anchor="Bluetooth.4.Core" target="https://www.bluetooth.com/specifications/specs/core-specification-4-0/">
        <front>
          <title>Bluetooth Core Specification 4.0</title>
          <author>
            <organization>Bluetooth SIG, Inc.</organization>
          </author>
          <date year="2010"/>
        </front>
</reference>

<reference anchor="Bluetooth.4.Core" target="https://www.bluetooth.com/specifications/specs/core-specification-4-0/">
        <front>
          <title>Bluetooth Core Specification 4.0</title>
          <author>
            <organization>Bluetooth SIG, Inc.</organization>
          </author>
          <date year="2010"/>
        </front>
</reference>

# Document History

   [[ To be removed from the final specification ]]

   -00 

   *  initial revision