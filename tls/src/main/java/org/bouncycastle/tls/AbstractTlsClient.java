package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.injection.InjectableKEMs;
import org.bouncycastle.tls.injection.InjectionPoint;
import org.bouncycastle.tls.injection.kems.InjectedKEM;
import org.bouncycastle.util.Integers;

/**
 * Base class for a TLS client.
 */
public abstract class AbstractTlsClient
    extends AbstractTlsPeer
    implements TlsClient
{
    protected TlsClientContext context;
    protected ProtocolVersion[] protocolVersions;
    protected int[] cipherSuites;

    protected Vector supportedGroups;
    protected Vector supportedSignatureAlgorithms;
    protected Vector supportedSignatureAlgorithmsCert;

    public AbstractTlsClient(TlsCrypto crypto)
    {
        super(crypto);
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
            TlsExtensionsUtils.readSupportedPointFormatsExtension(extensionData);
            return true;

        default:
            return false;
        }
    }

    protected Vector getNamedGroupRoles()
    {
        Vector namedGroupRoles = TlsUtils.getNamedGroupRoles(getCipherSuites());
        Vector sigAlgs = supportedSignatureAlgorithms, sigAlgsCert = supportedSignatureAlgorithmsCert;

        if ((null == sigAlgs || TlsUtils.containsAnySignatureAlgorithm(sigAlgs, SignatureAlgorithm.ecdsa))
            || (null != sigAlgsCert && TlsUtils.containsAnySignatureAlgorithm(sigAlgsCert, SignatureAlgorithm.ecdsa)))
        {
            TlsUtils.addToSet(namedGroupRoles, NamedGroupRole.ecdsa);
        }

        return namedGroupRoles;
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

    /**
     * RFC 9146 DTLS connection ID.
     * <p/>
     * The default {@link #getClientExtensions()} implementation calls this to get the connection_id extension the
     * client will send. As future communication doesn't include the connection IDs length, this should either
     * be fixed-length or include the connection ID's length. (see explanation in RFC 9146 4. "cid:")
     * @return The connection ID to use.
     */
    protected byte[] getNewConnectionID()
    {
        return null;
    }

    public TlsPSKIdentity getPSKIdentity() throws IOException
    {
        return null;
    }

    public TlsSRPIdentity getSRPIdentity() throws IOException
    {
        return null;
    }

    public TlsDHGroupVerifier getDHGroupVerifier()
    {
        return new DefaultTlsDHGroupVerifier();
    }

    public TlsSRPConfigVerifier getSRPConfigVerifier()
    {
        return new DefaultTlsSRPConfigVerifier();
    }

    protected Vector getCertificateAuthorities()
    {
        return null;
    }

    protected Vector getProtocolNames()
    {
        return null;
    }

    protected CertificateStatusRequest getCertificateStatusRequest()
    {
        return new CertificateStatusRequest(CertificateStatusType.ocsp, new OCSPStatusRequest(null, null));
    }

    /**
     * @return a {@link Vector} of {@link CertificateStatusRequestItemV2} (or null).
     */
    protected Vector getMultiCertStatusRequest()
    {
        return null;
    }

    protected Vector getSNIServerNames()
    {
        return null;
    }

    /**
     * The default {@link #getClientExtensions()} implementation calls this to determine which named
     * groups to include in the supported_groups extension for the ClientHello.
     * 
     * @param namedGroupRoles
     *            The {@link NamedGroupRole named group roles} for which there should be at
     *            least one supported group. By default this is inferred from the offered cipher
     *            suites and signature algorithms.
     * @return a {@link Vector} of {@link Integer}. See {@link NamedGroup} for group constants.
     */
    protected Vector getSupportedGroups(Vector namedGroupRoles)
    {
        TlsCrypto crypto = getCrypto();
        Vector supportedGroups = new Vector();

        // #tls-injection
        // Adding injected KEMs before:
        for (InjectedKEM kem : InjectionPoint.kems().kemsByOrdering(InjectableKEMs.Ordering.BEFORE)) {
            supportedGroups.add(kem.codePoint());
        }

        // #tls-injection
        // Skipping the default KEMS, if they are not needed:
        if (InjectionPoint.kems().defaultKemsNeeded()) {

            if (namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdh))) {
                TlsUtils.addIfSupported(supportedGroups, crypto,
                        new int[]{NamedGroup.x25519, NamedGroup.x448});
            }

            if (namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdh)) ||
                    namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdsa))) {
                TlsUtils.addIfSupported(supportedGroups, crypto,
                        new int[]{NamedGroup.secp256r1, NamedGroup.secp384r1});
            }

            if (namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.dh))) {
                TlsUtils.addIfSupported(supportedGroups, crypto,
                        new int[]{NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096});
            }
        }

        // #tls-injection
        // Adding injected KEMs after:
        for (InjectedKEM kem : InjectionPoint.kems().kemsByOrdering(InjectableKEMs.Ordering.AFTER)) {
            supportedGroups.add(kem.codePoint());
        }

        return supportedGroups;
    }

    protected Vector getSupportedSignatureAlgorithms()
    {
        return TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
    }

    protected Vector getSupportedSignatureAlgorithmsCert()
    {
        return null;
    }

    protected Vector getTrustedCAIndication()
    {
        return null;
    }

    protected short[] getAllowedClientCertificateTypes()
    {
        return null;
    }

    protected short[] getAllowedServerCertificateTypes()
    {
        return null;
    }

    public void init(TlsClientContext context)
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

        this.supportedGroups = null;
        this.supportedSignatureAlgorithms = null;
        this.supportedSignatureAlgorithmsCert = null;
    }

    public TlsSession getSessionToResume()
    {
        return null;
    }

    public Vector getExternalPSKs()
    {
        return null;
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

        boolean offeringTLSv13Plus = false;
        boolean offeringPreTLSv13 = false;
        boolean offeringDTLSv12 = false;        
        {
            ProtocolVersion[] supportedVersions = getProtocolVersions();
            for (int i = 0; i < supportedVersions.length; ++i)
            {
                ProtocolVersion supportedVersion = supportedVersions[i];
                if (TlsUtils.isTLSv13(supportedVersion))
                {
                    offeringTLSv13Plus = true;
                }
                else
                {
                    offeringPreTLSv13 = true;
                }

                offeringDTLSv12 |= ProtocolVersion.DTLSv12.equals(supportedVersion);
            }
        }

        Vector protocolNames = getProtocolNames();
        if (protocolNames != null)
        {
            TlsExtensionsUtils.addALPNExtensionClient(clientExtensions, protocolNames);
        }

        Vector sniServerNames = getSNIServerNames();
        if (sniServerNames != null)
        {
            TlsExtensionsUtils.addServerNameExtensionClient(clientExtensions, sniServerNames);
        }

        CertificateStatusRequest statusRequest = getCertificateStatusRequest();
        if (statusRequest != null)
        {
            TlsExtensionsUtils.addStatusRequestExtension(clientExtensions, statusRequest);
        }

        if (offeringTLSv13Plus)
        {
            Vector certificateAuthorities = getCertificateAuthorities();
            if (certificateAuthorities != null)
            {
                TlsExtensionsUtils.addCertificateAuthoritiesExtension(clientExtensions, certificateAuthorities);
            }
        }

        if (offeringPreTLSv13)
        {
            // TODO Shouldn't add if no offered cipher suite uses a block cipher?
            TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);

            Vector statusRequestV2 = getMultiCertStatusRequest();
            if (statusRequestV2 != null)
            {
                TlsExtensionsUtils.addStatusRequestV2Extension(clientExtensions, statusRequestV2);
            }

            Vector trustedCAKeys = getTrustedCAIndication();
            if (trustedCAKeys != null)
            {
                TlsExtensionsUtils.addTrustedCAKeysExtensionClient(clientExtensions, trustedCAKeys);
            }
        }

        ProtocolVersion clientVersion = context.getClientVersion();

        /*
         * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior to 1.2.
         * Clients MUST NOT offer it if they are offering prior versions.
         */
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
        {
            Vector supportedSigAlgs = getSupportedSignatureAlgorithms();
            if (null != supportedSigAlgs && !supportedSigAlgs.isEmpty())
            {
                this.supportedSignatureAlgorithms = supportedSigAlgs;

                TlsExtensionsUtils.addSignatureAlgorithmsExtension(clientExtensions, supportedSigAlgs);
            }

            Vector supportedSigAlgsCert = getSupportedSignatureAlgorithmsCert();
            if (null != supportedSigAlgsCert && !supportedSigAlgsCert.isEmpty())
            {
                this.supportedSignatureAlgorithmsCert = supportedSigAlgsCert;

                TlsExtensionsUtils.addSignatureAlgorithmsCertExtension(clientExtensions, supportedSigAlgsCert);
            }
        }

        Vector namedGroupRoles = getNamedGroupRoles();

        Vector supportedGroups = getSupportedGroups(namedGroupRoles);
        if (supportedGroups != null && !supportedGroups.isEmpty())
        {
            this.supportedGroups = supportedGroups;

            TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
        }

        if (offeringPreTLSv13)
        {
            if (namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdh))
                || namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdsa)))
            {
                TlsExtensionsUtils.addSupportedPointFormatsExtension(clientExtensions, new short[]{ ECPointFormat.uncompressed });
            }
        }

        {
            /*
             * RFC 7250 4.1. If the client has no remaining certificate types to send in the client hello, other than
             * the default X.509 type, it MUST omit the client_certificate_type extension [..].
             */
            short[] clientCertTypes = getAllowedClientCertificateTypes();
            if (clientCertTypes != null &&
                TlsUtils.containsNot(clientCertTypes, 0, clientCertTypes.length, CertificateType.X509))
            {
                TlsExtensionsUtils.addClientCertificateTypeExtensionClient(clientExtensions, clientCertTypes);
            }
        }

        {
            /*
             * RFC 7250 4.1. If the client has no remaining certificate types to send in the client hello, other than
             * the default X.509 certificate type, it MUST omit the entire server_certificate_type extension [..].
             */
            short[] serverCertTypes = getAllowedServerCertificateTypes();
            if (serverCertTypes != null &&
                TlsUtils.containsNot(serverCertTypes, 0, serverCertTypes.length, CertificateType.X509))
            {
                TlsExtensionsUtils.addServerCertificateTypeExtensionClient(clientExtensions, serverCertTypes);
            }
        }

        if (offeringDTLSv12)
        {
            /*
             * RFC 9146 3. When a DTLS session is resumed or renegotiated, the "connection_id" extension is
             * negotiated afresh.
             */
            byte[] clientConnectionID = getNewConnectionID();
            if (clientConnectionID != null)
            {
                TlsExtensionsUtils.addConnectionIDExtension(clientExtensions, clientConnectionID);
            }
        }

        return clientExtensions;
    }

    public Vector getEarlyKeyShareGroups()
    {
        /*
         * RFC 8446 4.2.8. Each KeyShareEntry value MUST correspond to a group offered in the
         * "supported_groups" extension and MUST appear in the same order. However, the values MAY
         * be a non-contiguous subset of the "supported_groups" extension and MAY omit the most
         * preferred groups.
         */

        // #tls-injection
        // Adding the first injected KEM (if there exists one):
        try {
            return TlsUtils.vectorOfOne(InjectionPoint.kems().firstKEM().codePoint());
        }
        catch (IllegalStateException e) {
            // KEM not found, continue with default algorithms
        }

        if (null == supportedGroups || supportedGroups.isEmpty())
        {
            return null;
        }
        if (supportedGroups.contains(Integers.valueOf(NamedGroup.x25519)))
        {
            return TlsUtils.vectorOfOne(Integers.valueOf(NamedGroup.x25519));
        }
        if (supportedGroups.contains(Integers.valueOf(NamedGroup.secp256r1)))
        {
            return TlsUtils.vectorOfOne(Integers.valueOf(NamedGroup.secp256r1));
        }
        return TlsUtils.vectorOfOne(supportedGroups.elementAt(0));
    }

    public boolean shouldUseCompatibilityMode()
    {
        return true;
    }

    public void notifyServerVersion(ProtocolVersion serverVersion)
        throws IOException
    {
    }

    public void notifySessionToResume(TlsSession session)
    {
    }

    public void notifySessionID(byte[] sessionID)
    {
    }

    public void notifySelectedCipherSuite(int selectedCipherSuite)
    {
    }

    public void notifySelectedPSK(TlsPSK selectedPSK) throws IOException
    {
    }

    public void processServerExtensions(Hashtable serverExtensions)
        throws IOException
    {
        if (null == serverExtensions)
        {
            return;
        }

        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        boolean isTLSv13 = TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion());

        if (isTLSv13)
        {
            /*
             * NOTE: From TLS 1.3 the protocol classes are strict about what extensions can appear.
             */
        }
        else
        {
            /*
             * RFC 5246 7.4.1.4.1. Servers MUST NOT send this extension.
             */
            checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_signature_algorithms);
            checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_signature_algorithms_cert);

            checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_supported_groups);

            int selectedCipherSuite = securityParameters.getCipherSuite();

            if (TlsECCUtils.isECCCipherSuite(selectedCipherSuite))
            {
                // We only support uncompressed format, this is just to validate the extension, if present.
                TlsExtensionsUtils.getSupportedPointFormatsExtension(serverExtensions);
            }
            else
            {
                checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_ec_point_formats);
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

    public void notifyNewSessionTicket(NewSessionTicket newSessionTicket)
        throws IOException
    {
    }
}
