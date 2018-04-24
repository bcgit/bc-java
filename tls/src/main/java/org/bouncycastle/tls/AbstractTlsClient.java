package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;

/**
 * Base class for a TLS client.
 */
public abstract class AbstractTlsClient
    extends AbstractTlsPeer
    implements TlsClient
{
    protected TlsKeyExchangeFactory keyExchangeFactory;

    protected TlsClientContext context;

    protected Vector supportedGroups;
    protected Vector supportedSignatureAlgorithms;
    protected short[] clientECPointFormats, serverECPointFormats;

    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;

    public AbstractTlsClient(TlsCrypto crypto)
    {
        this(crypto, new DefaultTlsKeyExchangeFactory());
    }

    public AbstractTlsClient(TlsCrypto crypto, TlsKeyExchangeFactory keyExchangeFactory)
    {
        super(crypto);

        this.keyExchangeFactory = keyExchangeFactory;
    }

    protected boolean allowUnexpectedServerExtension(Integer extensionType, byte[] extensionData)
        throws IOException
    {
        switch (extensionType.intValue())
        {
        case ExtensionType.supported_groups:
            /*
             * Exception added based on field reports that some servers do send this, although the
             * Supported Elliptic Curves Extension is clearly intended to be client-only. If
             * present, we still require that it is a valid EllipticCurveList.
             */
            TlsExtensionsUtils.readSupportedGroupsExtension(extensionData);
            return true;

        case ExtensionType.ec_point_formats:
            /*
             * Exception added based on field reports that some servers send this even when they
             * didn't negotiate an ECC cipher suite. If present, we still require that it is a valid
             * ECPointFormatList.
             */
            TlsECCUtils.readSupportedPointFormatsExtension(extensionData);
            return true;

        default:
            return false;
        }
    }

    protected void checkForUnexpectedServerExtension(Hashtable serverExtensions, Integer extensionType)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(serverExtensions, extensionType);
        if (extensionData != null && !allowUnexpectedServerExtension(extensionType, extensionData))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    protected TlsECConfigVerifier createECConfigVerifier()
    {
        int minimumCurveBits = TlsECCUtils.getMinimumCurveBits(selectedCipherSuite);
        return new DefaultTlsECConfigVerifier(minimumCurveBits, supportedGroups);
    }

    protected CertificateStatusRequest getCertificateStatusRequest()
    {
        return new CertificateStatusRequest(CertificateStatusType.ocsp, new OCSPStatusRequest(null, null));
    }

    protected Vector getSNIServerNames()
    {
        return null;
    }

    protected short[] getSupportedPointFormats()
    {
        return new short[]{ ECPointFormat.uncompressed, ECPointFormat.ansiX962_compressed_prime,
            ECPointFormat.ansiX962_compressed_char2, };
    }

    /**
     * The default {@link #getClientExtensions()} implementation calls this to determine which named
     * groups to include in the supported_groups extension for the ClientHello.
     * 
     * @param offeringDH
     *            True if we are offering any DH ciphersuites in ClientHello, so at least one DH
     *            group should be included.
     * @param offeringEC
     *            True if we are offering any EC ciphersuites in ClientHello, so at least one EC
     *            group should be included.
     * @return a {@link Vector} of {@link Integer}. See {@link NamedGroup} for group constants.
     */
    protected Vector getSupportedGroups(boolean offeringDH, boolean offeringEC)
    {
        Vector supportedGroups = new Vector();

        if (offeringEC)
        {
            /*
             * NOTE[fips]: These curves are recommended for FIPS. If any changes are made to how
             * this is configured, FIPS considerations need to be accounted for in BCJSSE.
             */
            supportedGroups.addElement(NamedGroup.secp256r1);
            supportedGroups.addElement(NamedGroup.secp384r1);
        }

        if (offeringDH)
        {
            supportedGroups.addElement(NamedGroup.ffdhe2048);
            supportedGroups.addElement(NamedGroup.ffdhe3072);
            supportedGroups.addElement(NamedGroup.ffdhe4096);
        }

        return supportedGroups;
    }

    protected Vector getSupportedSignatureAlgorithms()
    {
        return TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
    }

    public void init(TlsClientContext context)
    {
        this.context = context;
    }

    public TlsSession getSessionToResume()
    {
        return null;
    }

    public ProtocolVersion getClientHelloRecordLayerVersion()
    {
        // "{03,00}"
        // return ProtocolVersion.SSLv3;

        // "the lowest version number supported by the client"
        // return getMinimumVersion();

        // "the value of ClientHello.client_version"
        return getClientVersion();
    }

    public ProtocolVersion getClientVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    public boolean isFallback()
    {
        /*
         * RFC 7507 4. The TLS_FALLBACK_SCSV cipher suite value is meant for use by clients that
         * repeat a connection attempt with a downgraded protocol (perform a "fallback retry") in
         * order to work around interoperability problems with legacy servers.
         */
        return false;
    }

    public Hashtable getClientExtensions()
        throws IOException
    {
        Hashtable clientExtensions = new Hashtable();

        TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);
        TlsExtensionsUtils.addExtendedMasterSecretExtension(clientExtensions);

        Vector sniServerNames = getSNIServerNames();
        if (sniServerNames != null)
        {
            TlsExtensionsUtils.addServerNameExtension(clientExtensions, new ServerNameList(sniServerNames));
        }

        CertificateStatusRequest statusRequest = getCertificateStatusRequest();
        if (statusRequest != null)
        {
            TlsExtensionsUtils.addStatusRequestExtension(clientExtensions, statusRequest);
        }

        ProtocolVersion clientVersion = context.getClientVersion();

        /*
         * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior to 1.2.
         * Clients MUST NOT offer it if they are offering prior versions.
         */
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
        {
            this.supportedSignatureAlgorithms = getSupportedSignatureAlgorithms();

            TlsUtils.addSignatureAlgorithmsExtension(clientExtensions, supportedSignatureAlgorithms);
        }

        int[] cipherSuites = getCipherSuites();
        boolean offeringDH = TlsDHUtils.containsDHECipherSuites(cipherSuites);
        boolean offeringEC = TlsECCUtils.containsECCipherSuites(cipherSuites);

        if (offeringEC)
        {
            this.clientECPointFormats = getSupportedPointFormats();

            TlsECCUtils.addSupportedPointFormatsExtension(clientExtensions, clientECPointFormats);
        }

        Vector supportedGroups = getSupportedGroups(offeringDH, offeringEC);
        if (supportedGroups != null && !supportedGroups.isEmpty())
        {
            this.supportedGroups = supportedGroups;

            TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
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
            checkForUnexpectedServerExtension(serverExtensions, TlsUtils.EXT_signature_algorithms);

            checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_supported_groups);

            if (TlsECCUtils.isECCipherSuite(this.selectedCipherSuite))
            {
                this.serverECPointFormats = TlsECCUtils.getSupportedPointFormatsExtension(serverExtensions);
            }
            else
            {
                checkForUnexpectedServerExtension(serverExtensions, TlsECCUtils.EXT_ec_point_formats);
            }

            /*
             * RFC 7685 3. The server MUST NOT echo the extension.
             */
            checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_padding);
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

    public TlsCipher getCipher()
        throws IOException
    {
        int encryptionAlgorithm = TlsUtils.getEncryptionAlgorithm(selectedCipherSuite);
        int macAlgorithm = TlsUtils.getMACAlgorithm(selectedCipherSuite);

        if (encryptionAlgorithm < 0 || macAlgorithm < 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return context.getSecurityParameters().getMasterSecret().createCipher(new TlsCryptoParameters(context), encryptionAlgorithm, macAlgorithm);
    }

    public void notifyNewSessionTicket(NewSessionTicket newSessionTicket)
        throws IOException
    {
    }
}
