package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

public interface TlsServer {

    void init(TlsServerContext context);

    ProtocolVersion selectVersion(ProtocolVersion clientVersion) throws IOException;

    int selectCipherSuite(int[] offeredCipherSuites) throws IOException;

    short selectCompressionMethod(short[] offeredCompressionMethods) throws IOException;

    void notifySecureRenegotiation(boolean secureNegotiation) throws IOException;

    // Hashtables are (Integer -> byte[])
    Hashtable processClientExtensions(Hashtable serverExtensions) throws IOException;

    TlsCredentials getCredentials();

    TlsKeyExchange getKeyExchange() throws IOException;

    CertificateRequest getCertificateRequest();

    TlsCompression getCompression() throws IOException;

    TlsCipher getCipher() throws IOException;
}
