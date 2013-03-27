package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public abstract class AbstractTlsServer implements TlsServer {

    protected TlsCipherFactory cipherFactory;

    protected TlsServerContext context;

    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;

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

    public ProtocolVersion selectVersion(ProtocolVersion clientVersion) throws IOException {
        if (getMinimumVersion().isEqualOrEarlierVersionOf(clientVersion)) {
            ProtocolVersion maximumVersion = getMaximumVersion();
            if (clientVersion.isEqualOrEarlierVersionOf(maximumVersion)) {
                return clientVersion;
            }
            if (clientVersion.isLaterVersionOf(maximumVersion)) {
                return maximumVersion;
            }
        }
        throw new TlsFatalAlert(AlertDescription.protocol_version);
    }

    public int selectCipherSuite(int[] offeredCipherSuites) throws IOException {
        int[] cipherSuites = getCipherSuites();
        for (int i = 0; i < cipherSuites.length; ++i) {
            if (TlsProtocol.arrayContains(offeredCipherSuites, cipherSuites[i])) {
                return this.selectedCipherSuite = cipherSuites[i];
            }
        }
        throw new TlsFatalAlert(AlertDescription.handshake_failure);
    }

    public short selectCompressionMethod(short[] offeredCompressionMethods) throws IOException {
        short[] compressionMethods = getCompressionMethods();
        for (int i = 0; i < compressionMethods.length; ++i) {
            if (TlsProtocol.arrayContains(offeredCompressionMethods, compressionMethods[i])) {
                return this.selectedCompressionMethod = compressionMethods[i];
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

    public Hashtable processClientExtensions(Hashtable serverExtensions) throws IOException {
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
