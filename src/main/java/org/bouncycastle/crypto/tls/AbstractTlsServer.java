package org.bouncycastle.crypto.tls;

import java.io.IOException;

public abstract class AbstractTlsServer implements TlsServer {

    protected TlsCipherFactory cipherFactory;

    protected TlsServerContext context;

    protected int selectedCipherSuite;
    protected int selectedCompressionMethod;

    public AbstractTlsServer() {
        this(new DefaultTlsCipherFactory());
    }

    public AbstractTlsServer(TlsCipherFactory cipherFactory) {
        this.cipherFactory = cipherFactory;
    }

    public void init(TlsServerContext context) {
        this.context = context;
    }

    public ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.TLSv10;
    }

    public ProtocolVersion getMaximumVersion() {
        return ProtocolVersion.TLSv11;
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

    public CertificateRequest getCertificateRequest() {
        return null;
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
}
