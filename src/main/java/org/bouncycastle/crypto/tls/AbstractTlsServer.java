package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public abstract class AbstractTlsServer implements TlsServer {

    protected TlsCipherFactory cipherFactory;

    protected TlsServerContext context;

    protected ProtocolVersion clientVersion;
    protected Hashtable clientExtensions;

    protected ProtocolVersion serverVersion;
    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;
    protected Hashtable serverExtensions;

    public AbstractTlsServer() {
        this(new DefaultTlsCipherFactory());
    }

    public AbstractTlsServer(TlsCipherFactory cipherFactory) {
        this.cipherFactory = cipherFactory;
    }

    protected abstract int[] getCipherSuites();

    protected short[] getCompressionMethods() {
        return new short[] { CompressionMethod.NULL };
    }

    protected ProtocolVersion getMaximumVersion() {
        return ProtocolVersion.TLSv11;
    }

    protected ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.TLSv10;
    }

    public void init(TlsServerContext context) {
        this.context = context;
    }

    public void notifyClientVersion(ProtocolVersion clientVersion) throws IOException {
        this.clientVersion = clientVersion;
    }

    public void notifyOfferedCipherSuites(int[] offeredCipherSuites) throws IOException {
        int[] cipherSuites = getCipherSuites();
        for (int i = 0; i < cipherSuites.length; ++i) {
            if (TlsProtocol.arrayContains(offeredCipherSuites, cipherSuites[i])) {
                this.selectedCipherSuite = cipherSuites[i];
                return;
            }
        }
        throw new TlsFatalAlert(AlertDescription.handshake_failure);
    }

    public void notifyOfferedCompressionMethods(short[] offeredCompressionMethods)
        throws IOException {
        short[] compressionMethods = getCompressionMethods();
        for (int i = 0; i < compressionMethods.length; ++i) {
            if (TlsProtocol.arrayContains(offeredCompressionMethods, compressionMethods[i])) {
                this.selectedCompressionMethod = compressionMethods[i];
                return;
            }
        }
        throw new TlsFatalAlert(AlertDescription.handshake_failure);
    }

    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException {
        if (!secureRenegotiation) {
            /*
             * RFC 5746 3.6. In this case, some servers may want to terminate the handshake instead
             * of continuing; see Section 4.3 for discussion.
             */
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    public void processClientExtensions(Hashtable clientExtensions) throws IOException {
        this.clientExtensions = clientExtensions;
    }

    public ProtocolVersion getServerVersion() throws IOException {
        if (getMinimumVersion().isEqualOrEarlierVersionOf(clientVersion)) {
            ProtocolVersion maximumVersion = getMaximumVersion();
            if (clientVersion.isEqualOrEarlierVersionOf(maximumVersion)) {
                return serverVersion = clientVersion;
            }
            if (clientVersion.isLaterVersionOf(maximumVersion)) {
                return serverVersion = maximumVersion;
            }
        }
        throw new TlsFatalAlert(AlertDescription.protocol_version);
    }

    public int getSelectedCipherSuite() throws IOException {
        return selectedCipherSuite;
    }

    public short getSelectedCompressionMethod() throws IOException {
        return selectedCompressionMethod;
    }

    // Hashtable is (Integer -> byte[])
    public Hashtable getServerExtensions() throws IOException {
        if (TlsECCUtils.isECCCipherSuite(this.selectedCipherSuite)) {

            /*
             * TODO RFC 4429 5.1. A server that receives a ClientHello containing one or both of
             * these extensions MUST use the client's enumerated capabilities to guide its selection
             * of an appropriate cipher suite. One of the proposed ECC cipher suites must be
             * negotiated only if the server can successfully complete the handshake while using the
             * curves and point formats supported by the client [...].
             */
            this.serverExtensions = new Hashtable();
            TlsECCUtils.addSupportedPointFormatsExtension(serverExtensions, new short[] {
                ECPointFormat.uncompressed, ECPointFormat.ansiX962_compressed_char2,
                ECPointFormat.ansiX962_compressed_prime });
            return serverExtensions;
        }

        return null;
    }

    public Vector getServerSupplementalData() throws IOException {
        return null;
    }

    public CertificateRequest getCertificateRequest() {
        return null;
    }

    public void processClientSupplementalData(Vector clientSupplementalData) throws IOException {
        if (clientSupplementalData != null) {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public TlsCompression getCompression() throws IOException {
        switch (selectedCompressionMethod) {
        case CompressionMethod.NULL:
            return new TlsNullCompression();

        default:
            /*
             * Note: internal error here; we selected the compression method, so if we now can't
             * produce an implementation, we shouldn't have chosen it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void notifyHandshakeComplete() throws IOException {
    }
}
