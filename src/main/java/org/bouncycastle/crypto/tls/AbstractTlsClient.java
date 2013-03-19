package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

public abstract class AbstractTlsClient implements TlsClient {

    protected TlsCipherFactory cipherFactory;

    protected TlsClientContext context;

    protected int selectedCipherSuite;
    protected int selectedCompressionMethod;

    public AbstractTlsClient() {
        this(new DefaultTlsCipherFactory());
    }

    public AbstractTlsClient(TlsCipherFactory cipherFactory) {
        this.cipherFactory = cipherFactory;
    }

    public void init(TlsClientContext context) {
        this.context = context;
    }

    public ProtocolVersion getClientVersion() {
        return ProtocolVersion.TLSv11;
    }

    public Hashtable getClientExtensions() throws IOException {
        return null;
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
        // TODO Provide a method to get the minimum acceptable version
        if (serverVersion.getFullVersion() < ProtocolVersion.TLSv10.getFullVersion()) {
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
             * RFC 5746 3.4. If the extension is not present, the server does not support secure
             * renegotiation; set secure_renegotiation flag to FALSE. In this case, some clients may
             * want to terminate the handshake instead of continuing; see Section 4.1 for
             * discussion.
             */
            // throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    public void processServerExtensions(Hashtable serverExtensions) throws IOException {
        /*
         * TlsProtocolHandler validates that any server extensions received correspond to client
         * extensions sent. By default, we don't send any, and this method is not called.
         */
    }

    public TlsCompression getCompression() throws IOException {
        switch (selectedCompressionMethod) {
        case CompressionMethod.NULL:
            return new TlsNullCompression();

        default:
            /*
             * Note: internal error here; the TlsProtocolHandler verifies that the server-selected
             * compression method was in the list of client-offered compression methods, so if we
             * now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
