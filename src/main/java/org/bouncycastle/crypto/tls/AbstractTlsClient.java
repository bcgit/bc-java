package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public abstract class AbstractTlsClient
    extends AbstractTlsPeer
    implements TlsClient
{

    protected TlsCipherFactory cipherFactory;

    protected TlsClientContext context;

    protected Vector supportedSignatureAlgorithms;

    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;

    public AbstractTlsClient()
    {
        this(new DefaultTlsCipherFactory());
    }

    public AbstractTlsClient(TlsCipherFactory cipherFactory)
    {
        this.cipherFactory = cipherFactory;
    }

    public void init(TlsClientContext context)
    {
        this.context = context;
    }

    /**
     * RFC 5246 E.1. "TLS clients that wish to negotiate with older servers MAY send any value
     * {03,XX} as the record layer version number. Typical values would be {03,00}, the lowest
     * version number supported by the client, and the value of ClientHello.client_version. No
     * single value will guarantee interoperability with all old servers, but this is a complex
     * topic beyond the scope of this document."
     */
    public ProtocolVersion getClientHelloRecordLayerVersion()
    {
        // "{03,00}"
        // return ProtocolVersion.SSLv3;

        // "the lowest version number supported by the client"
        // return getMinimumServerVersion();

        // "the value of ClientHello.client_version"
        return getClientVersion();
    }

    public ProtocolVersion getClientVersion()
    {
        return ProtocolVersion.TLSv11;
    }

    public Hashtable getClientExtensions()
        throws IOException
    {

        Hashtable clientExtensions = null;

        ProtocolVersion clientVersion = context.getClientVersion();

        /*
         * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior to 1.2.
         * Clients MUST NOT offer it if they are offering prior versions.
         */
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
        {

            // TODO Provide a way for the user to specify the acceptable hash/signature algorithms.

            short[] hashAlgorithms = new short[]{HashAlgorithm.sha512, HashAlgorithm.sha384, HashAlgorithm.sha256,
                HashAlgorithm.sha224, HashAlgorithm.sha1};

            // TODO Sort out ECDSA signatures and add them as the preferred option here
            short[] signatureAlgorithms = new short[]{SignatureAlgorithm.rsa};

            this.supportedSignatureAlgorithms = new Vector();
            for (int i = 0; i < hashAlgorithms.length; ++i)
            {
                for (int j = 0; j < signatureAlgorithms.length; ++j)
                {
                    this.supportedSignatureAlgorithms.addElement(new SignatureAndHashAlgorithm(hashAlgorithms[i],
                        signatureAlgorithms[j]));
                }
            }

            /*
             * RFC 5264 7.4.3. Currently, DSA [DSS] may only be used with SHA-1.
             */
            this.supportedSignatureAlgorithms.addElement(new SignatureAndHashAlgorithm(HashAlgorithm.sha1,
                SignatureAlgorithm.dsa));

            if (clientExtensions == null)
            {
                clientExtensions = new Hashtable();
            }

            TlsUtils.addSignatureAlgorithmsExtension(clientExtensions, supportedSignatureAlgorithms);
        }

        return clientExtensions;
    }

    public ProtocolVersion getMinimumVersion()
    {
        return ProtocolVersion.TLSv10;
    }

    public void notifyServerVersion(ProtocolVersion serverVersion)
        throws IOException
    {
        if (!getMinimumVersion().isEqualOrEarlierVersionOf(serverVersion))
        {
            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }
    }

    public short[] getCompressionMethods()
    {
        return new short[]{CompressionMethod._null};
    }

    public void notifySessionID(byte[] sessionID)
    {
        // Currently ignored
    }

    public void notifySelectedCipherSuite(int selectedCipherSuite)
    {
        this.selectedCipherSuite = selectedCipherSuite;
    }

    public void notifySelectedCompressionMethod(short selectedCompressionMethod)
    {
        this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public void notifySecureRenegotiation(boolean secureRenegotiation)
        throws IOException
    {
        if (!secureRenegotiation)
        {
            /*
             * RFC 5746 3.4. In this case, some clients may want to terminate the handshake instead
             * of continuing; see Section 4.1 for discussion.
             */
            // throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    public void processServerExtensions(Hashtable serverExtensions)
        throws IOException
    {
        /*
         * TlsProtocol implementation validates that any server extensions received correspond to
         * client extensions sent. By default, we don't send any, and this method is not called.
         */
        if (serverExtensions != null)
        {
            /*
             * RFC 5246 7.4.1.4.1. Servers MUST NOT send this extension.
             */
            if (serverExtensions.containsKey(TlsUtils.EXT_signature_algorithms))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
    }

    public void processServerSupplementalData(Vector serverSupplementalData)
        throws IOException
    {
        if (serverSupplementalData != null)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public Vector getClientSupplementalData()
        throws IOException
    {
        return null;
    }

    public TlsCompression getCompression()
        throws IOException
    {
        switch (selectedCompressionMethod)
        {
        case CompressionMethod._null:
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

    public void notifyNewSessionTicket(NewSessionTicket newSessionTicket)
        throws IOException
    {
    }

    public void notifyHandshakeComplete()
        throws IOException
    {
    }
}
