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
fullname="Sasikumar Ganesan"
organization="MOSIP"
    [author.address]
    email = "sasi@mosip.io"

[[author]]
initials="N."
fullname="Ramesh Narayanan"
organization="MOSIP"
    [author.address]
    email = "ramesh@mosip.io"

%%%

.# Abstract

This document defines how Bluetooth Low Energy (BLE) can be used to request the presentation of verifiable credentials. It uses the request and response syntax as defined in [@!OpenID4VP].

{mainmatter}

# Introduction

This document enables Wallets and the Verifiers who have implemented [@!OpenID4VP] to request and receive verifiable presentations even if one or both of the entities do not have Internet connection by utilizing Bluetooth Low Energy (BLE). This document uses request and response syntax as defined in [@!OpenID4VP].

# Terms and Definitions

This draft uses the terms and definitions from [@!OpenID4VP], section 2. 

# Use Cases

## Admission control at a venue 

The user needs to present her electronic ticket (represented by a verifiable credentioal) when entering a venue. She opens her wallet and authenticates towards the wallet. She then scans the QR code at the entrance with her wallet. The wallet determines the credential (the ticket) required by the verifier and asks for consent to share the respective credential. The credential is then transmitted to the verifier, which, after validation, allows her to enter the venue, e.g. by opening the turnstile.  

# Overview 

This specification supports deployments, where the Verifier or the Wallet or both parties do not have an Internet connection or where use of an Internet connection is not desired to request and present Verifiable Credentials.

The protocol consists of the following steps:

1. Establishing a BLE connection
2. Requesting Verifiable Credentials, including authentication and authoprization of the Verifier
3. Presenting Verifiable credentials
4. Finalizing the exchange

Wallet and the Verifier MUST implement BLE according to the [@!Bluetooth.4.2.Core] specification. 

## Limitations

The following limitations in BLE stack 4.2 need to be considerate: 

1. Advertisement
    * The advertisement message can contain only a max. of 23 bytes in the request and 27 bytes in response.
    * The advertisement scan request can not have any custom data.
    * The scan response can have custom data. 
2. Timing
    * BLE Scanning and advertising are discrete events, so not every advertisement is received (an advertisment is sent for at most 30s) 
3. Throughput
    * The data rate, which can be expected, is about 0.10 Mbps. 
    * The calculation is as follows: 
      * Default MTU size is 23 bytes and max is 512 bytes
      * 14 bytes are overhead cost per packet (MTU).
      * 0.226 ~ 0.301 Mbps (Mega bits per second). 

## Protocol Flow Overview

Below is the diagram that illustrates the protocol flow:

~~~ ascii-art
+-------------+                                         +----------------+
|             |                                         |                |
|             |<---- (1) Connection setup request ------|                |
|             |          using QR code or discovery     |                |
|             |                                         |                |
|             |<---- (2) Wallet provides its -----------|                |
|             |          identifiers to the verifier    |                |
|             |                                         |                |
|             |                                         |                |
|             |----- (3) OpenID4VP Request over BLE, -->|                |
|             |          verify the requester           |                |
|             |       +----------+                      |                |
|             |       |          |                      |                |
|             |       | End-User |                      |                |
| Verifier    |       |          |<- (4) AuthN & AuthZ->|     Wallet     |
| (Peripheral |       |          |                      | (Central GAP   |
|  GAP Role,  |       +----------+                      |  Role,         |
|  Server)    |                                         |  Client)       |
|             |<---- (5) OpenID4VP Response over BLE ---|                |
|             |    (verifiable presentation as a chunk) |                |
|             |                                         |                |
|             |<---- (6) Transfer Summary Request ------|                |
|             |                                         |                |
|             |----- (7) Send Transfer Report---------->| (Repeat 4-6    |
|             |                                         | in case of     |
|             |<---- (8) Finalize the exchange ---------| error)         |
+-------------+          & Close connection             +----------------+
~~~
Figure: OpenID4VP over BLE Protocol Flow

Note: The arrow mark indicates a read or write by the wallet. 

   * "-->" Read by wallet
   * "<--" Write by wallet

1. Verifier and the Wallet establish the connection. This specification defines two mechanisms to do so: A QR code displayed by the Verifier and BLE Advertisement initiated by the Verifier. The Wallet obtains the advertisment data, including the Verifier's ephemeral key, using one of those messages. It then creates its own ephemeral key and derives the session secret key as defined in (#encryption). 
2. The Wallet sends its identification information to the Verifier, which also derives the session secret key as defined in (#encryption). All sub-sequent communication is encrypted using this session key.  
3. The Wallet reads the Presentation Request from the Verifier. 
4. The Wallet authenticates the user and obtains consent to share the Credential(s) with the Verifier.
5. The Wallet sends the Presentation Response to the Verifier containing one or more Verifiable Presentation(s).
6. The Wallet requests the Verifier for the transfer summary report.
7. The Verifier prepares the transfer report, which is read by the Wallet. In case of an error the steps 4 - 7 will be repeated.
8. If the transmission was concluded sucessful, the Wallet closes the connection.

# Connection Set up {#connection-set-up}

First, Verifier and the Wallet need to establish the connection. This specification defines two mechanisms to do so: BLE Advertisement initiated by the Verifier and QR code displayed by the Verifier.

Wallet and the Verifier MUST support LE Data Packet Length Extension according to [@!Bluetooth.4.2.Core] section 4.5.10.

Speaking in BLE terms, the Verifier takes the role of the "Peripheral GAP Role" whereas the Wallet takes the "Central GAP Role", i.e. the Verifier advertises the OpenID 4 VP service and the Wallet drives the protocol flow by reading data from and writing data to the Verifier.

## BLE Advertisement {#connection-ble}

This section describes how Verifier and the Wallet can establish a connection using Verifier-initiated BLE Advertisement. This mechanism can be used by the Verifiers when the use-case does not allow the End-Users to scan a QR code displayed on the Verifier's device, for example to ensure the safety of the Verifier.

The Verifier acts as the server and the Verifier service MUST contain the following characteristics:

Verifier Service UUID MUST be `00000001-5026-444A-9E0E-D6F2450F3A77`.

Verifier Service UUID for SCAN_RESP MUST be `00000002-5026-444A-9E0E-D6F2450F3A77`.

Note: The special service UUID for the `SCAN_RESP` is used to ensure support for iOS.

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

1. The Verifier starts the BLE advertisement (`PDU ADV_IND`) using the service UUID `00000001-5026-444A-9E0E-D6F2450F3A77`. The advertisment message starts with the prefix `OVP` (see below) and includes the first 5 bytes of the verifier's ephemeral key.
2. The Wallet scans the BLE layer and sends a `SCAN_REQ` to the Verifier acknowledging the advertisment. If there is only a single Verifier sending an advertisment message with the `OVP` prefix, the Wallet may automatically select this Verifier. Otherwise, if there are multiple verifiers the user is asked to choose. 
3. On Receiving the `SCAN_REQ`, the verifier sends a `SCAN_RESP` to the particular Wallet using the service UUID `00000002-5026-444A-9E0E-D6F2450F3A77`. This request contains the remaining 27 byte of the Verifier's ephemeral key.
4. The Wallet generates its ephemeral key pair and combines both keys to create a DHE secret key as described in (#encryption). The Wallet then sends an identify request (`IDENTIFY_REQ`, see (#identify-ble-request)) and submits its public key to the verifier in plain text. The Verifier calculates the DHE secret key based on its key pair and the wallet's public key as described in (#encryption).

Note: While the Verifier can be active for a long time and process multiple connections (based on the same Verifier key), it's expected that the range of the verifiers advertisement is limited based on the application's requirement. Verifiers are expected to provide the necessary controls to limit the range.
### BLE Advertisement Structure

BLE Advertisement Packet structure is defined as follows:

```
PDU:
    Header:
        PDU type: ADV_IND
        Tx Address: Random
        Rx Address: Random
    Payload: (25 bytes)
        Adv Address: Random address
        Adv Data: (17 byte)
            Adv Type: Complete Local Name
            flag: "LE General Discoverable Mode", "BR/EDR Not Supported"
            Data: OVPSTADONENTRY_8520f00989 (3 character + 11 character identifier name + 5 bytes of the random X25519 public key)
```

The data in the Advertisement Packet contain the prefix `OVP` indicating that the verifier is ready to accept connections for OpenID 4 VPs. A human readable name of the verifier is given in the next part.  The rest of the data packet after the `_` contains the first 5 bytes of the public key (example: `8520f00989´). (max. available size for data as defined by BLE is 20 byte). 

### Scan Response Structure

The Scan Response (`SCAN_RESP`) structure is defined as follows:

```
Payload: (31 bytes)
        Adv Address: Random address
        Adv Data: (31 byte)
            Data: 30a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
```
It provides the Wallet with the remaining 27 byte of the Verifier's ephemeral key.

## QR Code {#connection-scan-qr-ble}

This section describes how Verifier and the Wallet can establish a connection using a QR Code displayed by the Verifier.

The following figure shows the message exchange.

~~~ ascii-art
+------------+                       +-----------+
|            |-----PDU ADV_IND------>|           |
| Advertiser |<----Scan_QR_Code------|  Scanner  |
| (Verifier) |                       | (Wallet)  |
|            |<----IDENTIFY_REQ------|           |
+------------+                       +-----------+
~~~

Pre-requisites: The Verifier has opened it's application and displays a QR Code.

1. The End-User scans the QR Code (`Scan_QR_Code`) using the wallet app. The QR Code contains the name and the ephemeral public key of the Verifier. A non-normative example is shown below.

```
OPENID4VP://connect?name=STADONENTRY&key=8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a 
```
2. The Wallet generates its epheremal key pair and combines it with the Verifer's ephemeral key to create a DHE [secret key](#encryption). 
3. The Wallet makes identify request (`IDENTIFY_REQ`) and submits its public key to the verifier in plain text (see (#identify-ble-request)).
4. The Verifier calculates the DHE secret key based on its key pair and the wallet's public key.

The URL in the QR Code starts with the custom scheme `OPENID4VP` and the path is set to `connect`. The URL contains the following URI query parameters: 

* `name`: REQUIRED. A String containing the name of the verifier. 
* `key`: REQUIRED. A String containing the Verifier's ephemeral public key in hex encoding (as defined in Section 5 of [@!RFC4648]). 

A Custom URL scheme is used to enable activation of a Wallet of the End-User's choice thats capable of handling the request even if the QR Code is scanned with a camera app.

## Identify Request {#identify-ble-request}

This request is sent by the Wallet to the Verifier to finalize the connection establishment.

The Verifier's UUID service MUST be `00000006-5026-444A-9E0E-D6F2450F3A77`.

The request carries the following parameters: 

* `wallets x25519 key` <TBD required/optional, type, meaning>
* `nonce` <TBD required/optional, type, meaning>
* `encrypted:wallet provider clientid` <would remove for now and file issue instead>
* `encrypted:authentication context` <would remove for now and file issue instead>

## Session Key Computation

To calculate the session keys, the Wallet and the Verifier MUST perform ECKA-DH (Elliptic Curve Key Agreement Algorithm – Diffie-Hellman) as defined in BSI TR-03111. The `Zab` output defined in BSI TR-03111 MUST be used to derive two keys. 

The Verifier MUST derive its session key using HKDF as defined in [@!RFC5869] with the following parameters: 

* Hash: SHA-256 
* IKM: Zab 
* salt: SHA-256
* info: “SKVerifier” (encoded as ASCII string) 
* L: 32 octets 

The Wallet MUST derive its session key using HKDF as defined in [@!RFC5869] with the following parameters: 

* Hash: SHA-256 
* IKM: Zab 
* salt: SHA-256
* info: “SKWallet” (encoded as ASCII string) 
* L: 32 octets 

# BLE Message Handling
## Encryption {#encryption}

For encryption AES-256-GCM (192) (GCM: Galois Counter Mode) as defined in NIST SP 800-38D or ChaCha20 [@!RFC8439] MUST be used. 

The IV (Initialization Vector defined in NIST SP 800-38D) used for encryption MUST have the default length of 12 bytes for GCM, as specified in NIST SP 800-38D. The IV is the random nonce generated by the wallet provided in the Identify Request (see (#identify-ble-request)). 

The encryption of the data happens before any of the request size or response size is provided. So the entire data is encrypted with AES GCM 256 bit using the derived session keys. Due to this requirement there is no message counter requirement in this design. Also the fact that every wallet would send a random nonce and a random ephemeral public key, it is assumed the interaction is also save with a long term verifier key. This gives us with more probability of randomness in key derivation.  

The AAD (Additional Authenticated Data defined in NIST SP 800-38D) used as input for the GCM function MUST be an empty string. The plaintext used as input for the GCM function MUST be Wallet request or Wallet response. The value of the data element in the session establishment and session data messages as defined in 9.1.1.4 MUST be the concatenation of the ciphertext and all 16 bytes of the authentication tag (ciphertext || authentication tag).

## Messages Transmission {#message_transmission}

The protocol uses variable length messages to convey the presentation request and the presentation response. The design for those message exchanges uses the following pattern:  

For every of those requests/responses, there is one dedicated characterics to obtain the messages size, e.g. for the presentation request, this is the characteristics with the service UUID `00000004-5026-444A-9E0E-D6F2450F3A77`. 

The transmission of the actual payload is performed through another dedicated characteristics. For the presentation request, that is the service UUID `00000005-5026-444A-9E0E-D6F2450F3A77`. Depending on the MTU size, the sender splits the message into chucks and uses the transmission characteristics multiple times to transfer the chunks. 
QUESTION: is there an acknowledgment, if the receiver received the data or how does the sender know when to send the next chunk?

In order to detect packet loss, the sender requests a transfer summary report from the receiver after it has concluded the transmission. The transfer summary always uses the same Service UUIDs:

|Characteristic name | UUID                                 | Type| Description         |
|--------------------|--------------------------------------|-----------------------|---------------------|
|Transfer Summary Request| 00000009-5026-444A-9E0E-D6F2450F3A77 | Write(Wallet->Verifier)| Summary of the packets received |
|Transfer Summary Report| 0000000A-5026-444A-9E0E-D6F2450F3A77 | Notify(Verifier->Wallet)| Summary of the packets received |

Note: Verifier and Wallet may have different roles with respect to the transfer summary report characteristics depending on the direction of the data flow.

### Request Transmission {#packet-request-structure}

The JSON payload is encoded using JWS Compact serialization. The request size is the number of bytes that will be sent over BLE, the size of (JWS) in bytes. 

The actual content of the message can be a gzip [@!RFC1952]. In this case the size transmitted is the number of bytes of the gzip. Use the ID2 as per [@!RFC1952] to determine the gzip format. 

The `Request Size` characteristics is used to convey the request size. 

Once the size of the request is obtained, the `Request` characteristic is called to get the actual data. The characteristics is called repeatedly until all the requested data is received.

To read the complete Characteristic Value an ATT_READ_REQ PDU should be used for the first part of the value and ATT_READ_BLOB_REQ PDUs shall be used for the rest. The Value Offset parameter of each ATT_READ_BLOB_REQ PDU shall be set to the offset of the next octet within the Characteristic Value that has yet to be read. The ATT_READ_BLOB_REQ PDU is repeated until the ATT_READ_BLOB_RSP PDU’s Part Attribute Value parameter is shorter than (ATT_MTU – 1).

NOTE: In case the Request does not match Size then its assumed its corrupted and the same procedure is repeated again.
### Stream Packet Structure {#packet-stream-structure}

Using the 'Content Size' characteristics the wallet sets the size. Once we receive the confirmation about the write we start the 'Submit VC' as a stream. 'Submit VC' is called multiple times until all the data is sent.
                                                       
|  Chunk sequence no    |            Chunk payload            | Checksum value of data    |
|-----------------------|-------------------------------------|---------------------------|
|      (2 bytes)        |        (upto MTU-4 bytes - 2 bytes) | (2 bytes)        |
  
**Chunk Sequence No:** Running unsigned counter for the chunk and starts with 1 (Max 65535)

**Chunk Payload:** Chunk data.

**Checksum:** 2 bytes CRC16-CCITT-False (unsigned)

NOTE: Limit the max total size to ```~4kb``` for better performance while the protocol can handle larger size. In case the Request does not match Size then its assumed to be corrupted and the wallet is expected to send the requested chunks based on the ``` Transfer Summary Request ```.

In case of the CRC failure or decryption failure the ```Transfer summary report``` would be used to resend the specifc chunks

## Transfer Summary Request {#transfer-summary-request}

The wallet would request for a `Transfer Summary Request` once all the chunks are sent by the wallet. This is a write operation from the wallet.

## Transfer Summary Report {#transfer-summary-report}

When the Verifier receives the ```Transfer Summary Request```, the verifier MUST respond with the ```Transfer Summary Report```. This is a notification.

The following structure is used to send the summary report. 

|  Chunk sequence number            | Checksum                  |
|-----------------------------------|---------------------------|
|  (2 byte each upto max MTU)       |  (2 bytes)                |

** Chunk sequence number: ** List of chunks that are missing or failed CRC.

# OpenID4VP Request over BLE {#identify-request}

## BLE layer

On the BLE layer, the transmission of the payload is performed as described in (#message_transmission), where the following characteristics are used:  

1. Request Size `00000004-5026-444A-9E0E-D6F2450F3A77`: to obtain the size of the presentation request (calculation see (#packet-request-structure)).
2. Request `00000005-5026-444A-9E0E-D6F2450F3A77`: to obtain the actual JSON payload constituting the presentation request.

## Payload

The Request contains a signed request object containing the parameters as defined in [@!OpenID4VP].

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

# OpenID4VP Response over BLE {#identify-response}

## BLE

On the BLE layer, the transmission of the payload is performed as described in (#message_transmission), where the following characteristics are used:  

1. Response Size  `00000007-5026-444A-9E0E-D6F2450F3A77`:  to transmit the content size of the presentation response
2. Submit Response `00000008-5026-444A-9E0E-D6F2450F3A77`: to write the JSON payload of the presentation response as chunks.

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
# Disconnect

The Wallet will disconnect after providing a presentation response to the Verifier. 
The Verifier cannot disconnect but only timeout.

## BLE Connection closure {#connection-ble-close}

After data retrieval, the Wallet unsubscribes from all characteristics. Most often this is the default flow. While in certain cases the Verifier may be choose to cancel in between a transaction. This can be achieved by the ``` Disconnect ```. Whenever the wallet receives this notification the wallet is expected to initiate the disconnection. 

## Session Termination {#session-termination}

The session MUST be terminated if at least one of the following conditions occur: 

* After a time-out of no activity occurs. 
* If the Wallet does not want to receive any further requests. 
* If the Verifier does not want to send any further requests. 

Termination is as per the default BLE write. 

In case of a termination, the Wallet and Verifier MUST perform at least the following actions: 

* Destruction of session keys and related ephemeral key material 
* Closure of the communication channel used for data retrieval

## Connection re-establishment {#connection-ble-re-establishment}

In case of a lost connection a full flow is conducted again.

# UUID for Service Definition {#service-definition}

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

# Security Considerations {#security}

## Session Information

Both wallet and the Verifier MUST remove all the information about the session after its termination.

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
