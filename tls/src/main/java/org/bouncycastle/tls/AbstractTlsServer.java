package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Arrays;

/**
 * Base class for a TLS client.
 */
public abstract class AbstractTlsServer
    extends AbstractTlsPeer
    implements TlsServer
{
    protected TlsKeyExchangeFactory keyExchangeFactory;

    protected TlsServerContext context;

    protected ProtocolVersion clientVersion;
    protected int[] offeredCipherSuites;
    protected short[] offeredCompressionMethods;
    protected Hashtable clientExtensions;

    protected boolean encryptThenMACOffered;
    protected short maxFragmentLengthOffered;
    protected boolean truncatedHMacOffered;
    protected Vector supportedSignatureAlgorithms;
    protected int[] clientSupportedGroups;
    protected short[] clientECPointFormats, serverECPointFormats;
    protected CertificateStatusRequest certificateStatusRequest;

    protected ProtocolVersion serverVersion;
    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;
    protected Hashtable serverExtensions;

    public AbstractTlsServer(TlsCrypto crypto)
    {
        this(crypto, new DefaultTlsKeyExchangeFactory());
    }

    public AbstractTlsServer(TlsCrypto crypto, TlsKeyExchangeFactory keyExchangeFactory)
    {
        super(crypto);

        this.keyExchangeFactory = keyExchangeFactory;
    }

    protected boolean allowEncryptThenMAC()
    {
        return true;
    }

    protected boolean allowTruncatedHMac()
    {
        return false;
    }

    protected Hashtable checkServerExtensions()
    {
        return this.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(this.serverExtensions);
    }

    protected abstract int[] getCipherSuites();

    protected short[] getCompressionMethods()
    {
        return new short[]{ CompressionMethod._null };
    }

    protected ProtocolVersion getMaximumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    protected ProtocolVersion getMinimumVersion()
    {
        return ProtocolVersion.TLSv10;
    }

    protected int getMaximumNegotiableCurveBits()
    {
        // NOTE: BC supports all the current set of point formats so we don't check them here

        if (clientSupportedGroups == null)
        {
            /*
             * RFC 4492 4. A client that proposes ECC cipher suites may choose not to include these
             * extensions. In this case, the server is free to choose any one of the elliptic curves
             * or point formats [...].
             */
            return NamedGroup.getMaximumCurveBits();
        }

        int maxBits = 0;
        for (int i = 0; i < clientSupportedGroups.length; ++i)
        {
            maxBits = Math.max(maxBits, NamedGroup.getCurveBits(clientSupportedGroups[i]));
        }
        return maxBits;
    }

    protected int getMaximumNegotiableFiniteFieldBits()
    {
        if (clientSupportedGroups == null)
        {
            return NamedGroup.getMaximumFiniteFieldBits();
        }

        int maxBits = 0;
        for (int i = 0; i < clientSupportedGroups.length; ++i)
        {
            maxBits = Math.max(maxBits, NamedGroup.getFiniteFieldBits(clientSupportedGroups[i]));
        }
        return maxBits;
    }

    protected boolean isSelectableCipherSuite(int cipherSuite, int availCurveBits, int availFiniteFieldBits, Vector sigAlgs)
    {
        return Arrays.contains(this.offeredCipherSuites, cipherSuite)
            && TlsUtils.isValidCipherSuiteForVersion(cipherSuite, serverVersion)
            && availCurveBits >= TlsECCUtils.getMinimumCurveBits(cipherSuite)
            && availFiniteFieldBits >= TlsDHUtils.getMinimumFiniteFieldBits(cipherSuite)
            && TlsUtils.isValidCipherSuiteForSignatureAlgorithms(cipherSuite, sigAlgs);
    }

    protected boolean selectCipherSuite(int cipherSuite) throws IOException
    {
        this.selectedCipherSuite = cipherSuite;
        return true;
    }

    protected int selectCurve(int minimumCurveBits)
    {
        if (clientSupportedGroups == null)
        {
            return selectDefaultCurve(minimumCurveBits);
        }

        // Try to find a supported named group of the required size from the client's list.
        for (int i = 0; i < clientSupportedGroups.length; ++i)
        {
            int namedGroup = clientSupportedGroups[i];
            if (NamedGroup.getCurveBits(namedGroup) >= minimumCurveBits)
            {
                return namedGroup;
            }
        }

        return -1;
    }

    protected int selectDefaultCurve(int minimumCurveBits)
    {
        return minimumCurveBits <= 256 ? NamedGroup.secp256r1
            :  minimumCurveBits <= 384 ? NamedGroup.secp384r1
            :  minimumCurveBits <= 521 ? NamedGroup.secp521r1
            :  minimumCurveBits <= 571 ? NamedGroup.sect571r1
            :  -1;
    }

    protected TlsDHConfig selectDefaultDHConfig(int minimumFiniteFieldBits)
    {
        int namedGroup = minimumFiniteFieldBits <= 2048 ? NamedGroup.ffdhe2048
                      :  minimumFiniteFieldBits <= 3072 ? NamedGroup.ffdhe3072
                      :  minimumFiniteFieldBits <= 4096 ? NamedGroup.ffdhe4096
                      :  minimumFiniteFieldBits <= 6144 ? NamedGroup.ffdhe6144
                      :  minimumFiniteFieldBits <= 8192 ? NamedGroup.ffdhe8192
                      :  -1;

        return TlsDHUtils.createNamedDHConfig(namedGroup);
    }

    protected TlsDHConfig selectDHConfig() throws IOException
    {
        int minimumFiniteFieldBits = TlsDHUtils.getMinimumFiniteFieldBits(selectedCipherSuite);

        TlsDHConfig dhConfig = selectDHConfig(minimumFiniteFieldBits);
        if (dhConfig == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        return dhConfig;
    }

    protected TlsDHConfig selectDHConfig(int minimumFiniteFieldBits)
    {
        if (clientSupportedGroups == null)
        {
            return selectDefaultDHConfig(minimumFiniteFieldBits);
        }

        // Try to find a supported named group of the required size from the client's list.
        for (int i = 0; i < clientSupportedGroups.length; ++i)
        {
            int namedGroup = clientSupportedGroups[i];
            if (NamedGroup.getFiniteFieldBits(namedGroup) >= minimumFiniteFieldBits)
            {
                return new TlsDHConfig(namedGroup);
            }
        }

        return null;
    }

    protected TlsECConfig selectECConfig() throws IOException
    {
        int minimumCurveBits = TlsECCUtils.getMinimumCurveBits(selectedCipherSuite);

        int namedGroup = selectCurve(minimumCurveBits);
        if (namedGroup < 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        boolean compressed = TlsECCUtils.isCompressionPreferred(clientECPointFormats, namedGroup);

        TlsECConfig ecConfig = new TlsECConfig();
        ecConfig.setNamedGroup(namedGroup);
        ecConfig.setPointCompression(compressed);
        return ecConfig;
    }
    
    public void init(TlsServerContext context)
    {
        this.context = context;
    }

    public TlsSession getSessionToResume(byte[] sessionID)
    {
        return null;
    }

    public void notifyClientVersion(ProtocolVersion clientVersion)
        throws IOException
    {
        this.clientVersion = clientVersion;
    }

    public void notifyFallback(boolean isFallback) throws IOException
    {
        /*
         * RFC 7507 3. If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the highest
         * protocol version supported by the server is higher than the version indicated in
         * ClientHello.client_version, the server MUST respond with a fatal inappropriate_fallback
         * alert [..].
         */
        if (isFallback && getMaximumVersion().isLaterVersionOf(clientVersion))
        {
            throw new TlsFatalAlert(AlertDescription.inappropriate_fallback);
        }
    }

    public void notifyOfferedCipherSuites(int[] offeredCipherSuites)
        throws IOException
    {
        this.offeredCipherSuites = offeredCipherSuites;
    }

    public void notifyOfferedCompressionMethods(short[] offeredCompressionMethods)
        throws IOException
    {
        this.offeredCompressionMethods = offeredCompressionMethods;
    }

    public void processClientExtensions(Hashtable clientExtensions)
        throws IOException
    {
        this.clientExtensions = clientExtensions;

        if (clientExtensions != null)
        {
            this.encryptThenMACOffered = TlsExtensionsUtils.hasEncryptThenMACExtension(clientExtensions);

            this.maxFragmentLengthOffered = TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions);
            if (maxFragmentLengthOffered >= 0 && !MaxFragmentLength.isValid(maxFragmentLengthOffered))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            this.truncatedHMacOffered = TlsExtensionsUtils.hasTruncatedHMacExtension(clientExtensions);

            this.supportedSignatureAlgorithms = TlsUtils.getSignatureAlgorithmsExtension(clientExtensions);
            if (this.supportedSignatureAlgorithms != null)
            {
                /*
                 * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
                 * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
                 */
                if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }

            this.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);
            this.clientECPointFormats = TlsECCUtils.getSupportedPointFormatsExtension(clientExtensions);

            this.certificateStatusRequest = TlsExtensionsUtils.getStatusRequestExtension(clientExtensions);
        }

        /*
         * RFC 4429 4. The client MUST NOT include these extensions in the ClientHello message if it
         * does not propose any ECC cipher suites.
         * 
         * NOTE: This was overly strict as there may be ECC cipher suites that we don't recognize.
         * Also, RFC 7919 renamed 'elliptic_curves' to 'supported_groups' and now allows FFDHE (i.e.
         * non-ECC) groups. If ec_point_formats are unnecessarily present, it doesn't seem worth
         * failing the handshake over.
         */
//        if ((this.clientSupportedGroups != null || this.clientECPointFormats != null)
//            && !TlsECCUtils.containsECCipherSuites(offeredCipherSuites))
//        {
//            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
//        }
    }

    public ProtocolVersion getServerVersion()
        throws IOException
    {
        if (getMinimumVersion().isEqualOrEarlierVersionOf(clientVersion))
        {
            ProtocolVersion maximumVersion = getMaximumVersion();
            if (clientVersion.isEqualOrEarlierVersionOf(maximumVersion))
            {
                return serverVersion = clientVersion;
            }
            if (clientVersion.isLaterVersionOf(maximumVersion))
            {
                return serverVersion = maximumVersion;
            }
        }
        throw new TlsFatalAlert(AlertDescription.protocol_version);
    }

    public int getSelectedCipherSuite()
        throws IOException
    {
        /*
         * RFC 5246 7.4.3. In order to negotiate correctly, the server MUST check any candidate
         * cipher suites against the "signature_algorithms" extension before selecting them. This is
         * somewhat inelegant but is a compromise designed to minimize changes to the original
         * cipher suite design.
         */
        Vector sigAlgs = TlsUtils.getUsableSignatureAlgorithms(supportedSignatureAlgorithms);

        /*
         * RFC 4429 5.1. A server that receives a ClientHello containing one or both of these
         * extensions MUST use the client's enumerated capabilities to guide its selection of an
         * appropriate cipher suite. One of the proposed ECC cipher suites must be negotiated only
         * if the server can successfully complete the handshake while using the curves and point
         * formats supported by the client [...].
         */
        int availCurveBits = getMaximumNegotiableCurveBits();
        int availFiniteFieldBits = getMaximumNegotiableFiniteFieldBits();

        int[] cipherSuites = getCipherSuites();
        for (int i = 0; i < cipherSuites.length; ++i)
        {
            int cipherSuite = cipherSuites[i];
            if (isSelectableCipherSuite(cipherSuite, availCurveBits, availFiniteFieldBits, sigAlgs)
                && selectCipherSuite(cipherSuite))
            {
                return cipherSuite;
            }
        }
        throw new TlsFatalAlert(AlertDescription.handshake_failure);
    }

    public short getSelectedCompressionMethod()
        throws IOException
    {
        short[] compressionMethods = getCompressionMethods();
        for (int i = 0; i < compressionMethods.length; ++i)
        {
            if (Arrays.contains(offeredCompressionMethods, compressionMethods[i]))
            {
                return this.selectedCompressionMethod = compressionMethods[i];
            }
        }
        throw new TlsFatalAlert(AlertDescription.handshake_failure);
    }

    // Hashtable is (Integer -> byte[])
    public Hashtable getServerExtensions()
        throws IOException
    {
        if (this.encryptThenMACOffered && allowEncryptThenMAC())
        {
            /*
             * RFC 7366 3. If a server receives an encrypt-then-MAC request extension from a client
             * and then selects a stream or Authenticated Encryption with Associated Data (AEAD)
             * ciphersuite, it MUST NOT send an encrypt-then-MAC response extension back to the
             * client.
             */
            if (TlsUtils.isBlockCipherSuite(this.selectedCipherSuite))
            {
                TlsExtensionsUtils.addEncryptThenMACExtension(checkServerExtensions());
            }
        }

        if (this.maxFragmentLengthOffered >= 0 && MaxFragmentLength.isValid(maxFragmentLengthOffered))
        {
            TlsExtensionsUtils.addMaxFragmentLengthExtension(checkServerExtensions(), this.maxFragmentLengthOffered);
        }

        if (this.truncatedHMacOffered && allowTruncatedHMac())
        {
            TlsExtensionsUtils.addTruncatedHMacExtension(checkServerExtensions());
        }

        if (this.clientECPointFormats != null && TlsECCUtils.isECCipherSuite(this.selectedCipherSuite))
        {
            /*
             * RFC 4492 5.2. A server that selects an ECC cipher suite in response to a ClientHello
             * message including a Supported Point Formats Extension appends this extension (along
             * with others) to its ServerHello message, enumerating the point formats it can parse.
             */
            this.serverECPointFormats = new short[]{ ECPointFormat.uncompressed,
                ECPointFormat.ansiX962_compressed_prime, ECPointFormat.ansiX962_compressed_char2, };

            TlsECCUtils.addSupportedPointFormatsExtension(checkServerExtensions(), serverECPointFormats);
        }

        if (this.certificateStatusRequest != null)
        {
            /*
             * RFC 6066 8. If a server returns a "CertificateStatus" message, then the server MUST
             * have included an extension of type "status_request" with empty "extension_data" in
             * the extended server hello.
             */
            checkServerExtensions().put(TlsExtensionsUtils.EXT_status_request, TlsExtensionsUtils.createEmptyExtensionData());
        }

        return serverExtensions;
    }

    public Vector getServerSupplementalData()
        throws IOException
    {
        return null;
    }

    public CertificateStatus getCertificateStatus()
        throws IOException
    {
        return null;
    }

    public CertificateRequest getCertificateRequest()
        throws IOException
    {
        return null;
    }

    public void processClientSupplementalData(Vector clientSupplementalData)
        throws IOException
    {
        if (clientSupplementalData != null)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void notifyClientCertificate(Certificate clientCertificate)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
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
             * Note: internal error here; we selected the compression method, so if we now can't
             * produce an implementation, we shouldn't have chosen it!
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

    public NewSessionTicket getNewSessionTicket()
        throws IOException
    {
        /*
         * RFC 5077 3.3. If the server determines that it does not want to include a ticket after it
         * has included the SessionTicket extension in the ServerHello, then it sends a zero-length
         * ticket in the NewSessionTicket handshake message.
         */
        return new NewSessionTicket(0L, TlsUtils.EMPTY_BYTES);
    }
}
