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
%%%

.# Abstract

This document defines how Bluetooth Low Energy (BLE) can be used to request presentation of a verifiable credential. It uses request and response syntax defined in [@!OpenID4VP] specification.

{mainmatter}

# Introduction

This document enables Wallets and the Verifiers who have implemented [@!OpnID4VP] to be able to request and receive verifiable presentations even when one or both of the entities do not have Internet connection.

The document defines how Bluetooth Low Energy (BLE) can be used to request presentation of a verifiable credential.It uses request and response syntax defined in [@!OpenID4VP] specification.

# Terms and Definitions

verifiable credential
wallet
the verifier

//WIP

# Use Cases

## Use Case when only wallet is offline

## Use Case when only the verifier is offline

## Use Case when both wallet and the verifier are offline

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

Step 2 utilizes request and response syntax defined in [@!OpenID4VP] specification.

# Protocol Flow

~~~ ascii-art
+----------+                                         +----------------+
|          |                                         |                |
|          |<---- (1) Connection setup request ------|                |
|          |     (Ephemeral Key)                     |                |
|          |                                         |                |
|          |----- (2) OpenID4VP Request over BLE --->|                |
|          |                                         |                |
|          |       +----------+                      |                |
|          |       |          |                      |                |
|          |       | End-User |                      |                |
| Verifier |       |          |<--(2) AuthN & AuthZ->|     Wallet     |
|          |       |          |                      |                |
|          |       +----------+                      |                |
|          |                                         |                |
|          |<---- (3) OpenID4VP Response over BLE ---|                |
|          |      (verifiable presentation)          |                |
|          |                                         |                |
+----------+                                         +----------------+
~~~
Figure: OpenID4VP over BLE Protocol Flow


## Connection Setup


Wallet and the Verifier MUST support the Central role. The Wallet MUST act as GATT client. 

ToDo: name this as central client mode..?

For the BLE device retrieval    transmission    technology, the contents    of  the Alternative Carrier Record and Carrier  Configuration   Record(s) shall comply  with    Clause 8.3.3.1.1.2. 


The	UUID’s in the BleOptions structure shall be encoded using variant 1 (‘10x’b) as specified in RFC 4122.

Which one is better...

The UUID for peripheral server mode must be present if mdoc peripheral server mode is supported and must not be present if peripheral server mode is not supported.

The UUID for client central mode must be present if mdoc central client mode is supported and must not be present if central client mode is not supported.

The UUID’s used shall be 16-byte UUID’s that are unique for the transaction. The Peripheral device shall broadcast the service with the UUID as received during device engagement in the advertising packet. The Central device is then able to scan for the UUID and connect to the advertised service. However, the Central device may use a different mechanisms to identify the Peripheral device.

NOTE 1 BLE stacks in mobile devices can use scan filter and caching methods to manage congested environments and manage scan intervals for device energy consumption control. This can influence the connection time required when using UUIDs for the identification of the Peripheral device. 

NOTE 2 Finding the correct device to connect to is purely a practical problem. Connecting to the wrong mdoc reader does not have security implications, since due to the security methods described in Clause 9, the mdoc and mdoc reader will not setup a session with the wrong mdoc reader. Note however, that these mechanisms do not provide complete protection against a bad actor aiming to cause a denial of service attack by advertising as a fake mdoc reader

To ensure that the mdoc is connected to the correct mdoc reader. The mdoc may verify the Ident characteristic as described in Clause 8.3.3.1.4. The Ident characteristic value shall be calculated using the following procedure: 

Use HKDF an defined in RFC 5869 with the following parameters: 
• Hash: SHA-256 
• IKM: EdeviceKeyBytes (see Clause 9.1.1.4) 
• salt: (no salt value is provided) 
• info:”BLEIdent” (encoded as ASCII string) 
• L: 16 octets 
If the Ident characteristic received from the mdoc reader does not match the expected value, the mdoc shall disconnect from the mdoc reader. 

NOTE 3 The purpose of the Ident characteristic is only to verify whether the mdoc is connected to the correct mdoc reader before setting starting data retrieval. If the mdoc is connected to the wrong mdoc reader, session establishment will fail. Connecting and disconnecting to an mdoc reader takes a relatively large amount of time and it is therefore fastest to implement methods to identify the correct mdoc reader to connect to and not to rely purely on the Ident characteristic to identify the correct mdoc reader. 

After connection is setup, the GATT client may check to see if the GATT server supports the L2CAP transmission profile and, if so, use it to transfer data. See Annex A for more information. If the L2CAP transmission profile is used, Clause 8.3.3.1.1.5, Clause 8.3.3.1.1.6, Clause 8.3.3.1.1.7 and Clause 8.3.3.1.1.8 do not apply


## Security Considerations

## Session Information

Both wallet and the Verifier MUST remove all the information about the session after its termination.

## Discussion points
 
- not requiring nor recommending BLE secure connections.
- no support for the Peropheral role.