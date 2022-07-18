# OpenID for Verifiable Presentations over BLE


For device retrieval    using BLE,   the    mDL reader shall    support the mdoc central    client mode and mdoc peripheral server mode,    as  defined in  cluase  8.3.3.1.1. 
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
