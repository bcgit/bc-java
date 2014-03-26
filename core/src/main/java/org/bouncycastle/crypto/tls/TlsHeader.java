package org.bouncycastle.crypto.tls;

class TlsHeader
{

    short recordType;
    ProtocolVersion protocolVersion;
    int recordLength;
    
    TlsHeader(short recordType, ProtocolVersion protocolVersion,
            int length)
    {
        this.recordType = recordType;
        this.protocolVersion = protocolVersion;
        this.recordLength = length;
    }
    
}
