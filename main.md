%%%
title = "OpenID for Verifiable Presentations over BLE"
abbrev = "opendi4vp-offline"
ipr = "none"
workgroup = "OpenID Connect"
keyword = ["security", "openid", "ssi", "verifiable credential", "offline"]

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

This document defines how Bluetooth Low Energy (BLE) can be used to request presentation of verifiable credentials. It uses request and response syntax as defined in [@!OpenID4VP].

{mainmatter}

# Introduction

This document enables Wallets and the Verifiers who have implemented [@!OpenID4VP] to request and receive verifiable presentations even if one or both of the entities do not have Internet connection by utilizing Bluetooth Low Energy (BLE). This document uses request and response syntax as defined in [@!OpenID4VP].

# Terms and Definitions

This draft uses the terms and definitions from [@!OpenID4VP], section 2. 

# Use Cases

## Admission control at a venue 

The user needs to present her electronic ticket (represented by a verifiable credentioal) when entering a venue. She opens her wallet and authenticates towards the wallet. She then scans the QR code at the entrance with her wallet. The wallet determines the credential (the ticket) required by the verifier and asks for consent to share the respective credential. The credential is then transmitted to the verifier, which, after validation, allows her to enter the venue, e.g. by opening the turnstile.  

# Overview 

This specification supports deployments, where the Verifier or the Wallet or both parties do not have an Internet connection or where use of an Internet connection is not desired.

The protocol consists of the following steps:

1. Establishing a BLE connection
2. Verifying the parties
3. Exchanging verifiable credentials
4. Finalizing the exchange

Wallet and the Verifier MUST implement BLE according to the [@!Bluetooth.4.2.Core] specification . 

Step 1: Ephemeral keys to encrypt the session are exchanged. 

Step 2: Utilizes request and response syntax as defined in [@!OpenID4VP]. Identification and authentication of Verifier and Wallet can be implemented utilizing the established OpenID mechanisms (e.g. client id) or ```did``` . 

Step 3: Exchange VC and verify the same.

Step 4: Disconnect

# Limitation

The following limitations in BLE stack 4.2 need to be considerate: 

1. Advertisement
    * The advertisement message can contain only a max. of 29 bytes.
    * The advertisement scan request can not have any custom data.
    * The scan response can have custom data. 
2. Timing
    * BLE Scanning and advertising are discrete events, so not every advertisement is received (an advertisment is sent for at most 30s) 
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
|             |      (verifiable presentation as chunk) |                |
|             |                                         |                |
|             |<---- (5) Transfer Summary Request ------|                |
|             |                                         |                |
|             |----- (6) Send Transfer Report---------->| (Repeat 4-6    |
|             |                                         | in case of     |
|             |<----- (7) Finalize the exchange --------| error)         |
+-------------+          & Close connection             +----------------+
~~~
Figure: OpenID4VP over BLE Protocol Flow

Note: The arrow mark indicates a read or write by the wallet. 
-> Read by wallet
<- Write by wallet

1. Verifier and the Wallet establish the connection. This specification defines two mechanisms to do so: QR code displayed by the Verifier and BLE Advertisement initiated by the Verifier.
2. Wallet obtains the Presentation Request from the Verifier.
3. Wallet authenticates the user and obtains consent to share Credential(s) with the Verifier.
4. Wallet sends the Presentation Response to the Verifier containing Verifiable Presntation(s).
5. Wallet requests the Verifier for the transfer summary report.
6. Verifier sends transfer report (in case of error the steps 4-6 will be repeated) to Wallet. 
7. Verifier and the Wallet close connection.

## Details

Wallet MUST support the Central role and is responsible for connecting to the Verifier. The Verifier MUST support the Peripheral Role and should advertise its details. After the connection is established, the Wallet has the peripheral details and X25519 keys of the verifier. The sequence of flow is as described.

Step 1: Wallet generates a X25519 keys of its own and a random 8 byte nonce, combines to create a DHE secret key. The 16 byte nonce are ordered with first 8byte from the verifier and the second 8 byte from the wallet.
Step 2: Wallet makes identify request and submits its keys & nonce to the verifier in plain text.
Step 3: Wallet reads the Presentation request from the Verifier. (Encrypted with the secret key)
Step 4: Wallet authenticates the User and obtains consent
Step 5: Wallet submits the VC to the Verifier.
Step 6: Wallet requests the transfer summary.
Step 8: Verifier sends the transfer summary report.
Step 9: If error Wallet follows to send the missing chunk (Step 5-9). If success moves to Step 7
Step 7: The verifier accepts the VC if they could decrypt and validate the signature.
Step 8: Both the wallet and client records in their respective audit logs.


# Connection Set up {#connection-set-up}

First, Verifier and the Wallet need to establish the connection. This specification defines two mechanisms to do so: BLE Advertisement initiated by the Verifier and QR code displayed by the Verifier.

Wallet and the Verifier MUST support LE Data Packet Length Extension according to [@!Bluetooth.4.2.Core] section 4.5.10.

Speaking in BLE terms, the Verifier takes the role of the "Peripheral GAP Role" whereas the Wallet takes the "Central GAP Role", i.e. the Verifier advertises the OpenID 4 VP service and the Wallet drives the protocol flow by reading data from and writing data to the Verifier.

## Estabilishing Connection using BLE Advertisement {#connection-ble}

This section describes how Verifier and the Wallet can establish a connection by Verifier initiating BLE Advertisement. This mechanism can be used by the Verifiers when the use-case does not allow the End-Users to scan a QR code displayed on the Verifier's device, for example to ensure the safety of the Verifier.

The following figure shows the message exchange.

~~~ ascii-art
+------------+                       +-----------+
|            |-----PDU ADV_IND------>|           |
| Advertiser |<----SCAN_REQ----------| Scanner   |
| (Verifier) |-----SCAN_RESP-------->| (Wallet)  |
|            |<----IDENTIFY_REQ------|           |
+------------+                       +-----------+
~~~

Pre-requisites: The Verifier has opened it's application and started the mode that accepts OpenID4VP.

1. Verifier app starts BLE advertisement (`PDU ADV_IND`). (announcing the first 16 bytes of the verifier's key)
2. Wallet scans the BLE layer and filters the `OVP` automatically (in case it found only one). If there are multiple verifiers the user is asked to choose. 
3. Wallet connects to the Verifier (`SCAN_REQ`). The second 16 byte of the verifiers key is provided in the scan response (`SCAN_RESP`).
4. Wallet generates a X25519 ([@!RFC7748]) key pair of its own and combines to create a DHE secret key. 
5. Wallet makes identify request (`IDENTIFY_REQ`) and submits its public key to the verifier in plain text (see below). #identify characteristics 
6. Verifier calculates DHE secret key based on its key pair and the wallet's public key.

__Note:__ While the Verifier can be active for a long time and process multiple Connections (based on the same Verifier key) subsequently, the Verifier can only accept a single connection at a time.

__Note:__ Its expected that the range of the verifiers advertisement is limited based on the applications requirement. Verifiers are expected to provide the necessary controls to limit the range.

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
            Data: OVPSTADIONENTRANCE_8520f0098930a754748b (3 character + 15 character identifier name + 10 bytes ) 10 bytes of the random X25519 public key
```

The data in the Advertisement Packet contain the prefix "OVP" indicating that the verifier is ready to accept connections for OpenID 4 VPs. A human readable name of the verifier is given in the next part delimited by a trailing "_".  The rest of the data packet after the "_" contain the first 10 bytes of the public key (example: 8520f0098930a754748b) (max. available size 29 byte). 

BLE Advertisement -  OPENID4VP, first 10 byte of X25519 ([@!RFC7748] public key (max available size 29 byte), Response to the scan will send the remaining 22 byte of X25519 (7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a) and 8 byte random nonce, 

__Note:__ The SCAN_RESP has a special service UUID. This is to ensure support for IOS.

## Estabilishing Connection using QR Code {#connection-scan-qr-ble}

This section describes how Verifier and the Wallet can establish connection by Verifier displaying a QR Code scanned using the Wallet.

The following figure shows the message exchange.

~~~ ascii-art
+------------+                       +-----------+
|            |-----PDU ADV_IND------>|           |
|            |<----Scan_QR_Code------|           |
| Advertiser |<----SCAN_REQ----------| Scanner   |
| (Verifier) |-----SCAN_RESP-------->| (Wallet)  |
|            |<----IDENTIFY_REQ------|           |
+------------+                       +-----------+
~~~

Pre-requisites: The Verifier has opened it's application and displays a QR Code.

1. The user scans the QR Code (`Scan_QR_Code`), typically the wallet app, which contains the advertisment data as described in (#connection-ble).

All other steps are conducted as described in (#connection-ble).

The data are encoded in an URL as follows:

The URL starts with the custom scheme `OVPBLE`. The encoding of the actual data in the URL path follows the same rules given in (#connection-ble):

* The first part delimited by a "_" is a human readable identifier of the Verifier (RP). The first "_" in the advertisement should be used a delimiter. Other "_" could be associate with base64url.
* The rest of the path contains the verifier's ephemeral X25519 key in hex encoding (as defined in Section 5 of [@!RFC4648]). 

Sample QR Code 

```
OPENID4VP://connect?name=STADIONENTRANCE&key=8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a&nonce=6e91ab1b48396d3e 
```

How the connection setup request reaches a Wallet of a user's choice that capable of handling the request is out of scope of this specification(i.e. the usage of the Custom URL Schemes, Claimed URLs, etc.). The most certain way for a QR code to reach a target Wallet is to use a camera feature in a Wallet Application itself to scan a QR code.

# OpenID4VP Request over BLE

## BLE layer

On the BLE layer, the Wallet reads the following characteristics from the Verifier:  

1. Request Size (00000004-5026-444A-9E0E-D6F2450F3A77): used to obtain the size of the presentation request (calculation see below).
2. Request (00000005-5026-444A-9E0E-D6F2450F3A77): used to obtain the actual JSON payload constituting the presentation request.

The JSON payload is encoded using JWS Compact serialization. The request size is the number of bytes that will be sent over BLE, the size of (JWS) in bytes 

Note: Entire payload is encrypted on the BLE layer using the session key determined as defined above. 

## Payload

The Request (00000005-5026-444A-9E0E-D6F2450F3A77) contains a signed request object containing the parameters as defined in [@!OpenID4VP].

The following request parameters are supported by this specification:

* `iss`: REQUIRED. MUST contain the verifier's client_id.
* `presentation_definition`: CONDITIONAL. contains the verifier's requirements regarding verifiable credentials it wants to obtain from the wallet.
MUST not be present if a 'scope' parameter is present.
* `scope`: CONDITIONAL. The scope value MUST represent a credential presentation request. This parameter MUST NOT be present if a `presentation_definition` parameter is present. 
* `nonce`: REQUIRED. This value is used to securely bind the verifiable presentation(s) provided by the wallet to the particular transaction.
* `aud`: OPTIONAL. This value identifies the wallet issuer (as intended recipient of the presentation request).

The parameters `response_type` and `redirect_uri` MUST NOT be present in the request.

The following is a non normative example of a request before signing:

```json
{
   "iss":"s6BhdRkqt3",
   "aud":"https://wallet.example.com",
   "nonce":"n-0S6_WzA2Mj",
   "presentation_definition":{
      "id":"example",
      "input_descriptors":[
         {
            "id":"id_credential",
            "format":{
               "jwt_vc":{
                  "proof_type":[
                     "JsonWebSignature2020"
                  ]
               }
            },
            "constraints":{
               "fields":[
                  {
                     "path":[
                        "$.vc.type"
                     ],
                     "filter":{
                        "type":"array",
                        "contains":{
                           "const":"IDCredential"
                        }
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

## BLE

On the BLE layer the wallet writes the following characteristics in order to send a presentation response:


1. Response Size  (00000007-5026-444A-9E0E-D6F2450F3A77): used to transmit the content size of the presentation response
2. Submit Response (00000008-5026-444A-9E0E-D6F2450F3A77): used to write the JSON payload of the presentation response as chunks.

__Note:__ All payload is encrypted on the BLE layer using the session key determined as defined above. 

## Payload

The response contains the parameters as defined in Section 6 of [!@OpenID4VP] in JSON encoding. 

The following is a non normative example of a response before signing:

```json
{
   "presentation_submission":{
      "definition_id":"example",
      "id":"id_credential",
      "descriptor_map":[
         {
            "id":"id_credential",
            "path":"$",
            "format":"jwt_vp",
            "path_nested":{
               "path":"$.vp.verifiableCredential[0]",
               "format":"jwt_vc"
            }
         }
      ]
   },
   "vp_token":"eyJhbGciOiJFUzI...XK9n2861OaHDQ"
}
```

# BLE Details
## UUID for Service Definition {#service-definition}

The Verifier acts as the server and the Verifier service MUST contain the following characteristics:

Verifier Service UUID MUST be `00000001-5026-444A-9E0E-D6F2450F3A77`.

Verifier Service UUID for SCAN_RESP MUST be `00000002-5026-444A-9E0E-D6F2450F3A77`.

|Characteristic name | UUID                                 | Type| Description         |
|--------------------|--------------------------------------|-----------------------|---------------------|
|Request Size        | 00000004-5026-444A-9E0E-D6F2450F3A77 | Read(Wallet->Verifier) | Get the request size|
|Request             | 00000005-5026-444A-9E0E-D6F2450F3A77 | Read(Wallet->Verifier) | Get the request JSON|
|Identify            | 00000006-5026-444A-9E0E-D6F2450F3A77 | Write(Wallet->Verifier)| Wallet identifies as chunks           |
|Content Size        | 00000007-5026-444A-9E0E-D6F2450F3A77 | Write(Wallet->Verifier)| Submit the content size                |
|Submit VC           | 00000008-5026-444A-9E0E-D6F2450F3A77 | Write(Wallet->Verifier)| VC stream as chunks |
|Transfer Summary Request| 00000009-5026-444A-9E0E-D6F2450F3A77 | Write(Wallet->Verifier)| Summary of the packets received |
|Transfer Summary Report| 0000000A-5026-444A-9E0E-D6F2450F3A77 | Notify(Verifier->Wallet)| Summary of the packets received |
|Disconnect            | 0000000B-5026-444A-9E0E-D6F2450F3A77 | Notify(Verifier->Wallet) | In case verifier wants to disconnect due to unforseen error |


TODO: We should plan to register our service with Bluetooth SIG. This is a must and has to be discussed. 

ToDo: Check if there are conventions to the UUID. Original in ISO is `00000001-A123-48CE-896B-4C76973373E6`.

## Identity Request

ToDo: Need to elaborate.

The wallet has to identify itself with the following parameters.
`wallets ed25519 key`, `nonce`, `encrypted:wallet provider did` ,`encrypted:authentication context`


## Presentation Request (Request Characteristic)

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

                                                                   
|  Chunk sequence no    |            Chunk payload            | Checksum value of data    |
|-----------------------|-------------------------------------|---------------------------|
|      (2 bytes)        |        (upto MTU-4 bytes - 2 bytes) | (2 bytes)        |
  
**Chunk Sequence No:** Running unsigned counter for the chunk and starts with 1 (Max 65535)

**Chunk Payload:** Chunk data.

**Checksum:** 2 bytes CRC16-CCITT-False (unsigned)

__NOTE__: Limit the max total size to ```~4kb``` for better performance while the protocol can handle larger. In case the Request does not match Size then its assumed to be corrupted and the wallet is expected to send the requested chunks based on the ``` Transfer Summary Request ```.

In case of the CRC failure or decryption failure the ```Transfer summary report``` would be used to resend the specifc chunks

## Stream Read Packet Structure

The ```Request Size``` is first called to get the actual size of the request. Once the size of the request is obtained the ```Request``` characteristics is called to get the actual data. The characteristics is called repeatedly until all the requested data is received.

To read the complete Characteristic Value an ATT_READ_REQ PDU should be used for the first part of the value and ATT_READ_BLOB_REQ PDUs shall used for the rest. The Value Offset parameter of each ATT_READ_BLOB_REQ PDU shall be set to the offset of the next octet within the Characteristic Value that has yet to be read. The ATT_READ_BLOB_REQ PDU is repeated until the ATT_READ_BLOB_RSP PDU’s Part Attribute Value parameter is shorter than (ATT_MTU – 1).

__NOTE__: In case the Request does not match Size then its assumed its corrupted and the same procedure is repeated again.

## Transfer Summary Request:

The wallet would request for a ```Transfer Summary Request``` once all the chunks are sent by the wallet. This is a notification.

## Transfer Summary Report:

When the Verifier receives the ```Transfer Summary Request``` the verifier would respond with the ```Transfer Summary Report```

The following structure is used to send the summary report. 

|  Chunk sequence number            | Checksum                  |
|-----------------------------------|---------------------------|
|  (1 byte each upto max MTU)       |  (2 bytes)                |

** Chunk sequence number: ** List of chunks that are missing or failed CRC.

## Connection closure 

After data retrieval, the Wallet unsubscribes from all characteristics. Most often this is the default flow. While in certain cases the Verifier may be choose to cancel in between a transaction. This can be achieved by the ``` Disconnect ```. Whenever the wallet receives this notification the wallet is expected to initiate the disconnection. 

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

1. The Wallet obtains Verifier's ephemeral key pair and partial random nonce in the Connection Setup Request from BLE Advertisement or a QR Code.
2. The Wallet generates an ephemeral key pair
3. The Wallet communicates its ephemeral public key & a 12 byte random nonce to the Verifier in the Identity Request.
4. The Verifier derives an encryption key using the Wallet's public key received in the Idenity Request, and encrypts Presentation Request using it.
5. The Wallet derives an encryption key using the Verifier's public key received in the Connection Set Up phase, decrypts Presentation Request and encrypts Presentation Response using it.
6. The Verifier decrypts Presentation Response using the encryption key computed in step 4.

Note that Connection Setup Request itself defined in (#connection-set-up) MUST NOT be encrypted.

ToDo: No algorithm identifier since looks like we are doing only X25519?

## Session Key Computation

To calculate the session keys, the Wallet and the Verifier MUST perform ECKA-DH (Elliptic Curve Key Agreement Algorithm – Diffie-Hellman) as defined in BSI TR-03111. The Zab output defined in BSI TR-03111 MUST be used to derive 2 keys. 

The Verifier MUST derive session key using HKDF as defined in [@!RFC5869] with the following parameters: 

* Hash: SHA-256 
* IKM: Zab 
* salt: SHA-256
* info: “SKVerifier” (encoded as ASCII string) 
* L: 32 octets 

The Wallet MUST derive session key using HKDF as defined in [@!RFC5869] with the following parameters: 

* Hash: SHA-256 
* IKM: Zab 
* salt: SHA-256
* info: “SKWallet” (encoded as ASCII string) 
* L: 32 octets 

For encryption AES-256-GCM (192) (GCM: Galois Counter Mode)  as defined in NIST SP 800-38D or ChaCha20 [@!RFC8439] MUST be used. 

ToDo: Can we do ChaCha20? Rather than AES 256 GCM? The fact that ChaCha20 is more streaming is atractive.

The IV (Initialization Vector defined in NIST SP 800-38D) used for encryption MUST have the default length of 12 bytes for GCM, as specified in NIST SP 800-38D. The IV is the random nonce generated by the wallet. 

The encryption of the data happens before any of the request size or response size is provided. So the entire data is encrypted with AES GCM 256 bit using the derived session keys. Due to this requirement there is no message counter requirement in this design. Also the fact that every wallet would send a random nonce and a random ephemeral public key we can assume a safe interaction with a long term verifier key. This gives us with more probability of randomness in key derivation.  

The AAD (Additional Authenticated Data defined in NIST SP 800-38D) used as input for the GCM function MUST be an empty string. The plaintext used as input for the GCM function MUST be Wallet request or Wallet response. The value of the data element in the session establishment and session data messages as defined in 9.1.1.4 MUST be the concatenation of the ciphertext and all 16 bytes of the authentication tag (ciphertext || authentication tag).

# Security Considerations

## Session Information

Wallet MUST remove all the information about the session after its termination. Verifier might choose to do so based on their mode of operation.


## Verifier Authentication

How does the wallet authenticate the Verifier? The verifier signs the presentation request. 

## Session Binding

How does the Verifier know a particular response is tied to a particular request? It evaluates the nonce and aud value of the presentation to match the nonce of the request and its client id. 

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

<reference anchor="Bluetooth.4.2.Core" target=" https://www.bluetooth.com/specifications/specs/core-specification-4-2/">
        <front>
          <title>Bluetooth Core Specification 4.2</title>
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
