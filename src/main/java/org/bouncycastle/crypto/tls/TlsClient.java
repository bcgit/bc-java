package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public interface TlsClient
    extends TlsPeer
{

    void init(TlsClientContext context);

    ProtocolVersion getClientHelloRecordLayerVersion();

    ProtocolVersion getClientVersion();

    int[] getCipherSuites();

    short[] getCompressionMethods();

    // Hashtable is (Integer -> byte[])
    Hashtable getClientExtensions()
        throws IOException;

    void notifyServerVersion(ProtocolVersion selectedVersion)
        throws IOException;

    void notifySessionID(byte[] sessionID);

    void notifySelectedCipherSuite(int selectedCipherSuite);

    void notifySelectedCompressionMethod(short selectedCompressionMethod);

    void notifySecureRenegotiation(boolean secureNegotiation)
        throws IOException;

    // Hashtable is (Integer -> byte[])
    void processServerExtensions(Hashtable serverExtensions)
        throws IOException;

    // Vector is (SupplementalDataEntry)
    void processServerSupplementalData(Vector serverSupplementalData)
        throws IOException;

    TlsKeyExchange getKeyExchange()
        throws IOException;

    TlsAuthentication getAuthentication()
        throws IOException;

    // Vector is (SupplementalDataEntry)
    Vector getClientSupplementalData()
        throws IOException;

    TlsCompression getCompression()
        throws IOException;

    TlsCipher getCipher()
        throws IOException;

    /**
     * RFC 5077 3.3. NewSessionTicket Handshake Message
     * <p/>
     * This method will be called (only) when a NewSessionTicket handshake message is received. The
     * ticket is opaque to the client and clients MUST NOT examine the ticket under the assumption
     * that it complies with e.g. <i>RFC 5077 4. Recommended Ticket Construction</i>.
     *
     * @param newSessionTicket The ticket.
     * @throws IOException
     */
    void notifyNewSessionTicket(NewSessionTicket newSessionTicket)
        throws IOException;

    void notifyHandshakeComplete()
        throws IOException;
}
