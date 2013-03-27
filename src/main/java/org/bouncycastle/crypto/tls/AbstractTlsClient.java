package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Integers;

public abstract class AbstractTlsClient implements TlsClient {

    protected TlsCipherFactory cipherFactory;

    protected TlsClientContext context;

    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;

    public AbstractTlsClient() {
        this(new DefaultTlsCipherFactory());
    }

    public AbstractTlsClient(TlsCipherFactory cipherFactory) {
        this.cipherFactory = cipherFactory;
    }

    public void init(TlsClientContext context) {
        this.context = context;
    }

    /**
     * RFC 5246 E.1. "TLS clients that wish to negotiate with older servers MAY send any value
     * {03,XX} as the record layer version number. Typical values would be {03,00}, the lowest
     * version number supported by the client, and the value of ClientHello.client_version. No
     * single value will guarantee interoperability with all old servers, but this is a complex
     * topic beyond the scope of this document."
     */
    public ProtocolVersion getClientHelloRecordLayerVersion() {
        // "{03,00}"
        // return ProtocolVersion.SSLv3;

        // "the lowest version number supported by the client"
        // return getMinimumServerVersion();

        // "the value of ClientHello.client_version"
        return getClientVersion();
    }

    public ProtocolVersion getClientVersion() {
        return ProtocolVersion.TLSv11;
    }

    public Hashtable getClientExtensions() throws IOException {

        if (TlsECCUtils.containsECCCipherSuites(getCipherSuites())) {
            /*
             * RFC 4492 5.1. A client that proposes ECC cipher suites in its ClientHello message
             * appends these extensions (along with any others), enumerating the curves it supports
             * and the point formats it can parse. Clients SHOULD send both the Supported Elliptic
             * Curves Extension and the Supported Point Formats Extension.
             */
            Hashtable clientExtensions = new Hashtable();
            TlsECCUtils.addSupportedEllipticCurvesExtension(clientExtensions, new int[] {
                NamedCurve.secp256r1, NamedCurve.secp224r1, NamedCurve.secp192r1 });
            TlsECCUtils.addSupportedPointFormatsExtension(clientExtensions, new short[] {
                ECPointFormat.uncompressed, ECPointFormat.ansiX962_compressed_char2,
                ECPointFormat.ansiX962_compressed_prime });
            return clientExtensions;
        }

        return null;
    }

    public ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.TLSv10;
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
        if (!getMinimumVersion().isEqualOrEarlierVersionOf(serverVersion)) {
            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }
    }

    public short[] getCompressionMethods() {
        return new short[] { CompressionMethod.NULL };
    }

    public void notifySessionID(byte[] sessionID) {
        // Currently ignored
    }

    public void notifySelectedCipherSuite(int selectedCipherSuite) {
        this.selectedCipherSuite = selectedCipherSuite;
    }

    public void notifySelectedCompressionMethod(short selectedCompressionMethod) {
        this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException {
        if (!secureRenegotiation) {
            /*
             * RFC 5746 3.4. In this case, some clients may want to terminate the handshake instead
             * of continuing; see Section 4.1 for discussion.
             */
            // throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    public void processServerExtensions(Hashtable serverExtensions) throws IOException {
        /*
         * TlsProtocol implementation validates that any server extensions received correspond to
         * client extensions sent. By default, we don't send any, and this method is not called.
         */
    }

    public void processServerSupplementalData(Vector serverSupplementalData) throws IOException {
        if (serverSupplementalData != null) {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public Vector getClientSupplementalData() throws IOException {
        return null;
    }

    public TlsCompression getCompression() throws IOException {
        switch (selectedCompressionMethod) {
        case CompressionMethod.NULL:
            return new TlsNullCompression();

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected compression method was in the list of client-offered compression
             * methods, so if we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void notifyHandshakeComplete() throws IOException {
    }
}
