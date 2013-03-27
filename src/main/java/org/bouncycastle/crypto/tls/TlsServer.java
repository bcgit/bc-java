package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public interface TlsServer {

    void init(TlsServerContext context);

    void notifyClientVersion(ProtocolVersion clientVersion) throws IOException;

    void notifyOfferedCipherSuites(int[] offeredCipherSuites) throws IOException;

    void notifyOfferedCompressionMethods(short[] offeredCompressionMethods) throws IOException;

    void notifySecureRenegotiation(boolean secureNegotiation) throws IOException;

    // Hashtable is (Integer -> byte[])
    void processClientExtensions(Hashtable clientExtensions) throws IOException;

    ProtocolVersion getServerVersion() throws IOException;

    int getSelectedCipherSuite() throws IOException;

    short getSelectedCompressionMethod() throws IOException;

    // Hashtable is (Integer -> byte[])
    Hashtable getServerExtensions() throws IOException;

    // Vector is (SupplementalDataEntry)
    Vector getServerSupplementalData() throws IOException;

    TlsCredentials getCredentials() throws IOException;

    TlsKeyExchange getKeyExchange() throws IOException;

    CertificateRequest getCertificateRequest();

    // Vector is (SupplementalDataEntry)
    void processClientSupplementalData(Vector clientSupplementalData) throws IOException;

    TlsCompression getCompression() throws IOException;

    TlsCipher getCipher() throws IOException;

    void notifyHandshakeComplete() throws IOException;
}
