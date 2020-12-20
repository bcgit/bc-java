package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

/**
 * Base class for a TLS server.
 */
public abstract class AbstractTlsServer
    extends AbstractTlsPeer
    implements TlsServer
{
    protected TlsServerContext context;
    protected ProtocolVersion[] protocolVersions;
    protected int[] cipherSuites;

    protected int[] offeredCipherSuites;
    protected Hashtable clientExtensions;

    protected boolean encryptThenMACOffered;
    protected short maxFragmentLengthOffered;
    protected boolean truncatedHMacOffered;
    protected boolean clientSentECPointFormats;
    protected CertificateStatusRequest certificateStatusRequest;
    protected Vector statusRequestV2;
    protected Vector trustedCAKeys;

    protected int selectedCipherSuite;
    protected Vector clientProtocolNames;
    protected ProtocolName selectedProtocolName;

    protected final Hashtable serverExtensions = new Hashtable();

    public AbstractTlsServer(TlsCrypto crypto)
    {
        super(crypto);
    }

    protected boolean allowCertificateStatus()
    {
        return true;
    }

    protected boolean allowEncryptThenMAC()
    {
        return true;
    }

    protected boolean allowMultiCertStatus()
    {
        return false;
    }

    protected boolean allowTruncatedHMac()
    {
        return false;
    }

    protected boolean allowTrustedCAIndication()
    {
        return false;
    }

    /** @deprecated Use 'serverExtensions' directly, it is now never null */
    protected Hashtable checkServerExtensions()
    {
        return serverExtensions;
    }

    protected int getMaximumNegotiableCurveBits()
    {
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
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
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
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

    protected Vector getProtocolNames()
    {
        return null;
    }

    protected boolean isSelectableCipherSuite(int cipherSuite, int availCurveBits, int availFiniteFieldBits, Vector sigAlgs)
    {
        // TODO[tls13] The version check should be separated out (eventually select ciphersuite before version)
        return TlsUtils.isValidVersionForCipherSuite(cipherSuite, context.getServerVersion())
            && availCurveBits >= TlsECCUtils.getMinimumCurveBits(cipherSuite)
            && availFiniteFieldBits >= TlsDHUtils.getMinimumFiniteFieldBits(cipherSuite)
            && TlsUtils.isValidCipherSuiteForSignatureAlgorithms(cipherSuite, sigAlgs);
    }

    protected boolean preferLocalCipherSuites()
    {
        return false;
    }

    protected boolean selectCipherSuite(int cipherSuite) throws IOException
    {
        this.selectedCipherSuite = cipherSuite;
        return true;
    }

    protected int selectDH(int minimumFiniteFieldBits)
    {
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null)
        {
            return selectDHDefault(minimumFiniteFieldBits);
        }

        // Try to find a supported named group of the required size from the client's list.
        for (int i = 0; i < clientSupportedGroups.length; ++i)
        {
            int namedGroup = clientSupportedGroups[i];
            if (NamedGroup.getFiniteFieldBits(namedGroup) >= minimumFiniteFieldBits)
            {
                return namedGroup;
            }
        }

        return -1;
    }

    protected int selectDHDefault(int minimumFiniteFieldBits)
    {
        return minimumFiniteFieldBits <= 2048 ? NamedGroup.ffdhe2048
            :  minimumFiniteFieldBits <= 3072 ? NamedGroup.ffdhe3072
            :  minimumFiniteFieldBits <= 4096 ? NamedGroup.ffdhe4096
            :  minimumFiniteFieldBits <= 6144 ? NamedGroup.ffdhe6144
            :  minimumFiniteFieldBits <= 8192 ? NamedGroup.ffdhe8192
            :  -1;
    }

    protected int selectECDH(int minimumCurveBits)
    {
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null)
        {
            return selectECDHDefault(minimumCurveBits);
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

    protected int selectECDHDefault(int minimumCurveBits)
    {
        return minimumCurveBits <= 256 ? NamedGroup.secp256r1
            :  minimumCurveBits <= 384 ? NamedGroup.secp384r1
            :  minimumCurveBits <= 521 ? NamedGroup.secp521r1
            :  -1;
    }

    protected ProtocolName selectProtocolName() throws IOException
    {
        Vector serverProtocolNames = getProtocolNames();
        if (null == serverProtocolNames || serverProtocolNames.isEmpty())
        {
            return null;
        }

        ProtocolName result = selectProtocolName(clientProtocolNames, serverProtocolNames);
        if (null == result)
        {
            throw new TlsFatalAlert(AlertDescription.no_application_protocol);
        }

        return result;
    }

    protected ProtocolName selectProtocolName(Vector clientProtocolNames, Vector serverProtocolNames)
    {
        for (int i = 0; i < serverProtocolNames.size(); ++i)
        {
            ProtocolName serverProtocolName = (ProtocolName)serverProtocolNames.elementAt(i);
            if (clientProtocolNames.contains(serverProtocolName))
            {
                return serverProtocolName;
            }
        }
        return null;
    }

    protected boolean shouldSelectProtocolNameEarly()
    {
        return true;
    }

    public void init(TlsServerContext context)
    {
        this.context = context;

        this.protocolVersions = getSupportedVersions();
        this.cipherSuites = getSupportedCipherSuites();
    }

    public ProtocolVersion[] getProtocolVersions()
    {
        return protocolVersions;
    }

    public int[] getCipherSuites()
    {
        return cipherSuites;
    }

    public void notifyHandshakeBeginning() throws IOException
    {
        super.notifyHandshakeBeginning();

        this.offeredCipherSuites = null;
        this.clientExtensions = null;
        this.encryptThenMACOffered = false;
        this.maxFragmentLengthOffered = 0;
        this.truncatedHMacOffered = false;
        this.clientSentECPointFormats = false;
        this.certificateStatusRequest = null;
        this.selectedCipherSuite = -1;
        this.selectedProtocolName = null;
        this.serverExtensions.clear();
    }

    public TlsSession getSessionToResume(byte[] sessionID)
    {
        return null;
    }

    public byte[] getNewSessionID()
    {
        return null;
    }

    public void notifySession(TlsSession session)
    {
    }

    public void notifyClientVersion(ProtocolVersion clientVersion)
        throws IOException
    {
    }

    public void notifyFallback(boolean isFallback) throws IOException
    {
        /*
         * RFC 7507 3. If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the highest
         * protocol version supported by the server is higher than the version indicated in
         * ClientHello.client_version, the server MUST respond with a fatal inappropriate_fallback
         * alert [..].
         */
        if (isFallback)
        {
            ProtocolVersion[] serverVersions = getProtocolVersions();
            ProtocolVersion clientVersion = context.getClientVersion();

            ProtocolVersion latestServerVersion;
            if (clientVersion.isTLS())
            {
                latestServerVersion = ProtocolVersion.getLatestTLS(serverVersions);
            }
            else if (clientVersion.isDTLS())
            {
                latestServerVersion = ProtocolVersion.getLatestDTLS(serverVersions);
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            if (null != latestServerVersion && latestServerVersion.isLaterVersionOf(clientVersion))
            {
                throw new TlsFatalAlert(AlertDescription.inappropriate_fallback);
            }
        }
    }

    public void notifyOfferedCipherSuites(int[] offeredCipherSuites)
        throws IOException
    {
        this.offeredCipherSuites = offeredCipherSuites;
    }

    public void processClientExtensions(Hashtable clientExtensions)
        throws IOException
    {
        this.clientExtensions = clientExtensions;

        if (null != clientExtensions)
        {
            this.clientProtocolNames = TlsExtensionsUtils.getALPNExtensionClient(clientExtensions);
            
            if (shouldSelectProtocolNameEarly())
            {
                if (null != clientProtocolNames && !clientProtocolNames.isEmpty())
                {
                    this.selectedProtocolName = selectProtocolName();
                }
            }

            this.encryptThenMACOffered = TlsExtensionsUtils.hasEncryptThenMACExtension(clientExtensions);
            this.truncatedHMacOffered = TlsExtensionsUtils.hasTruncatedHMacExtension(clientExtensions);
            this.certificateStatusRequest = TlsExtensionsUtils.getStatusRequestExtension(clientExtensions);
            this.statusRequestV2 = TlsExtensionsUtils.getStatusRequestV2Extension(clientExtensions);
            this.trustedCAKeys = TlsExtensionsUtils.getTrustedCAKeysExtensionClient(clientExtensions);

            // We only support uncompressed format, this is just to validate the extension, and note its presence.
            this.clientSentECPointFormats = (null != TlsExtensionsUtils.getSupportedPointFormatsExtension(clientExtensions));

            this.maxFragmentLengthOffered = TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions);
            if (maxFragmentLengthOffered >= 0 && !MaxFragmentLength.isValid(maxFragmentLengthOffered))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
    }

    public ProtocolVersion getServerVersion()
        throws IOException
    {
        ProtocolVersion[] serverVersions = getProtocolVersions();
        ProtocolVersion[] clientVersions = context.getClientSupportedVersions();

        for (int i = 0; i < clientVersions.length; ++i)
        {
            ProtocolVersion clientVersion = clientVersions[i];
            if (ProtocolVersion.contains(serverVersions, clientVersion))
            {
                return clientVersion;
            }
        }

        throw new TlsFatalAlert(AlertDescription.protocol_version);
    }

    public int[] getSupportedGroups() throws IOException
    {
        // TODO[tls13] The rest of this class assumes all named groups are supported
        return new int[]{ NamedGroup.x25519, NamedGroup.x448, NamedGroup.secp256r1, NamedGroup.secp384r1,
            NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096 };
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
        Vector sigAlgs = TlsUtils.getUsableSignatureAlgorithms(
            context.getSecurityParametersHandshake().getClientSigAlgs());

        /*
         * RFC 4429 5.1. A server that receives a ClientHello containing one or both of these
         * extensions MUST use the client's enumerated capabilities to guide its selection of an
         * appropriate cipher suite. One of the proposed ECC cipher suites must be negotiated only
         * if the server can successfully complete the handshake while using the curves and point
         * formats supported by the client [...].
         */
        int availCurveBits = getMaximumNegotiableCurveBits();
        int availFiniteFieldBits = getMaximumNegotiableFiniteFieldBits();

        int[] cipherSuites = TlsUtils.getCommonCipherSuites(offeredCipherSuites, getCipherSuites(),
            preferLocalCipherSuites());

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

    // Hashtable is (Integer -> byte[])
    public Hashtable getServerExtensions()
        throws IOException
    {
        final boolean isTLSv13 = TlsUtils.isTLSv13(context);

        if (isTLSv13)
        {
            if (null != this.certificateStatusRequest && allowCertificateStatus())
            {
                /*
                 * TODO[tls13] RFC 8446 4.4.2.1. OCSP Status and SCT Extensions.
                 * 
                 * OCSP information is carried in an extension for a CertificateEntry.
                 */
            }
        }
        else
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
                    TlsExtensionsUtils.addEncryptThenMACExtension(serverExtensions);
                }
            }

            if (this.truncatedHMacOffered && allowTruncatedHMac())
            {
                TlsExtensionsUtils.addTruncatedHMacExtension(serverExtensions);
            }

            if (this.clientSentECPointFormats && TlsECCUtils.isECCCipherSuite(this.selectedCipherSuite))
            {
                /*
                 * RFC 4492 5.2. A server that selects an ECC cipher suite in response to a ClientHello
                 * message including a Supported Point Formats Extension appends this extension (along
                 * with others) to its ServerHello message, enumerating the point formats it can parse.
                 */
                TlsExtensionsUtils.addSupportedPointFormatsExtension(serverExtensions,
                    new short[]{ ECPointFormat.uncompressed });
            }

            // TODO[tls13] See RFC 8446 4.4.2.1
            if (null != this.statusRequestV2 && allowMultiCertStatus())
            {
                /*
                 * RFC 6961 2.2. If a server returns a "CertificateStatus" message in response to a
                 * "status_request_v2" request, then the server MUST have included an extension of type
                 * "status_request_v2" with empty "extension_data" in the extended server hello..
                 */
                TlsExtensionsUtils.addEmptyExtensionData(serverExtensions, TlsExtensionsUtils.EXT_status_request_v2);
            }
            else if (null != this.certificateStatusRequest && allowCertificateStatus())
            {
                /*
                 * RFC 6066 8. If a server returns a "CertificateStatus" message, then the server MUST
                 * have included an extension of type "status_request" with empty "extension_data" in
                 * the extended server hello.
                 */
                TlsExtensionsUtils.addEmptyExtensionData(serverExtensions, TlsExtensionsUtils.EXT_status_request);
            }

            if (null != this.trustedCAKeys && allowTrustedCAIndication())
            {
                TlsExtensionsUtils.addTrustedCAKeysExtensionServer(serverExtensions);
            }
        }

        if (this.maxFragmentLengthOffered >= 0 && MaxFragmentLength.isValid(maxFragmentLengthOffered))
        {
            TlsExtensionsUtils.addMaxFragmentLengthExtension(serverExtensions, this.maxFragmentLengthOffered);
        }

        return serverExtensions;
    }

    public void getServerExtensionsForConnection(Hashtable serverExtensions) throws IOException
    {
        if (!shouldSelectProtocolNameEarly())
        {
            if (null != clientProtocolNames && !clientProtocolNames.isEmpty())
            {
                this.selectedProtocolName = selectProtocolName();
            }
        }

        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        if (null == selectedProtocolName)
        {
            serverExtensions.remove(TlsExtensionsUtils.EXT_application_layer_protocol_negotiation);
        }
        else
        {
            TlsExtensionsUtils.addALPNExtensionServer(serverExtensions, selectedProtocolName);
        }
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

    public TlsPSKIdentityManager getPSKIdentityManager() throws IOException
    {
        return null;
    }

    public TlsSRPLoginParameters getSRPLoginParameters() throws IOException
    {
        return null;
    }

    public TlsDHConfig getDHConfig() throws IOException
    {
        int minimumFiniteFieldBits = TlsDHUtils.getMinimumFiniteFieldBits(selectedCipherSuite);
        int namedGroup = selectDH(minimumFiniteFieldBits);
        return TlsDHUtils.createNamedDHConfig(context, namedGroup);
    }

    public TlsECConfig getECDHConfig() throws IOException
    {
        int minimumCurveBits = TlsECCUtils.getMinimumCurveBits(selectedCipherSuite);
        int namedGroup = selectECDH(minimumCurveBits);
        return TlsECCUtils.createNamedECConfig(context, namedGroup);
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
