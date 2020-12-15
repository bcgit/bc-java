package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCStandardConstants;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.CertificateStatus;
import org.bouncycastle.tls.CertificateStatusType;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.IdentifierType;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.TrustedAuthority;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;

abstract class JsseUtils
{
    private static final boolean provRequireCloseNotify =
        PropertyUtils.getBooleanSystemProperty("com.sun.net.ssl.requireCloseNotify", true);
    private static final boolean provTlsAllowLegacyMasterSecret =
        PropertyUtils.getBooleanSystemProperty("jdk.tls.allowLegacyMasterSecret", true);
    private static final boolean provTlsAllowLegacyResumption =
        PropertyUtils.getBooleanSystemProperty("jdk.tls.allowLegacyResumption", false);
    private static final boolean provTlsUseExtendedMasterSecret =
        PropertyUtils.getBooleanSystemProperty("jdk.tls.useExtendedMasterSecret", true);

    static final Set<BCCryptoPrimitive> KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC =
        Collections.unmodifiableSet(EnumSet.of(BCCryptoPrimitive.KEY_AGREEMENT));
    static final Set<BCCryptoPrimitive> KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC =
        Collections.unmodifiableSet(EnumSet.of(BCCryptoPrimitive.KEY_ENCAPSULATION));
    static final Set<BCCryptoPrimitive> SIGNATURE_CRYPTO_PRIMITIVES_BC =
        Collections.unmodifiableSet(EnumSet.of(BCCryptoPrimitive.SIGNATURE));

    protected static X509Certificate[] EMPTY_CHAIN = new X509Certificate[0];

    static class BCUnknownServerName extends BCSNIServerName
    {
        BCUnknownServerName(int nameType, byte[] encoded)
        {
            super(nameType, encoded);
        }
    }

    static boolean allowLegacyMasterSecret()
    {
        return provTlsAllowLegacyMasterSecret;
    }

    static boolean allowLegacyResumption()
    {
        return provTlsAllowLegacyResumption;
    }

    static <T> T[] clone(T[] ts)
    {
        return null == ts ? null : ts.clone();
    }

    static boolean contains(String[] values, String value)
    {
        for (int i = 0; i < values.length; ++i)
        {
            if (value.equals(values[i]))
            {
                return true;
            }
        }
        return false;
    }

    static <T> boolean containsNull(T[] ts)
    {
        for (int i = 0; i < ts.length; ++i)
        {
            if (null == ts[i])
            {
                return true;
            }
        }
        return false;
    }

    static String[] copyOf(String[] data, int newLength)
    {
        String[] tmp = new String[newLength];
        System.arraycopy(data, 0, tmp, 0, Math.min(data.length, newLength));
        return tmp;
    }

    static TlsCredentialedDecryptor createCredentialedDecryptor(JcaTlsCrypto crypto, BCX509Key x509Key)
    {
        PrivateKey privateKey = x509Key.getPrivateKey();
        Certificate certificate = getCertificateMessage(crypto, x509Key.getCertificateChain());

        return new JceDefaultTlsCredentialedDecryptor(crypto, certificate, privateKey);
    }

    static TlsCredentialedSigner createCredentialedSigner(TlsContext context, JcaTlsCrypto crypto, BCX509Key x509Key,
        SignatureAndHashAlgorithm sigAndHashAlg)
    {
        /*
         * TODO[jsse] Before proceeding with EC credentials, check (TLS 1.2+) that the used curve
         * was actually declared in the client's elliptic_curves/named_groups extension.
         */

        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
        PrivateKey privateKey = x509Key.getPrivateKey();
        Certificate certificate = getCertificateMessage(crypto, x509Key.getCertificateChain());

        return new JcaDefaultTlsCredentialedSigner(cryptoParams, crypto, privateKey, certificate, sigAndHashAlg);
    }

    static TlsCredentialedSigner createCredentialedSigner13(TlsContext context, JcaTlsCrypto crypto, BCX509Key x509Key,
        SignatureAndHashAlgorithm sigAndHashAlg, byte[] certificateRequestContext)
    {
        /*
         * TODO[jsse] Before proceeding with EC credentials, check (TLS 1.2+) that the used curve
         * was actually declared in the client's elliptic_curves/named_groups extension.
         */

        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
        PrivateKey privateKey = x509Key.getPrivateKey();
        Certificate certificate = getCertificateMessage13(crypto, x509Key.getCertificateChain(),
            certificateRequestContext);

        return new JcaDefaultTlsCredentialedSigner(cryptoParams, crypto, privateKey, certificate, sigAndHashAlg);
    }

    static boolean equals(Object a, Object b)
    {
        return a == b || (null != a && null != b && a.equals(b));
    }

    static String[] resize(String[] data, int count)
    {
        if (count < data.length)
        {
            data = copyOf(data, count);
        }
        return data;
    }

    static String getApplicationProtocol(SecurityParameters securityParameters)
    {
        if (null == securityParameters || !securityParameters.isApplicationProtocolSet())
        {
            return null;
        }

        ProtocolName applicationProtocol = securityParameters.getApplicationProtocol();
        if (null == applicationProtocol)
        {
            return "";
        }

        return applicationProtocol.getUtf8Decoding();
    }

    static String getAuthTypeClient(short signatureAlgorithm)
    {
        /*
         * For use with checkClientTrusted calls on a trust manager.
         * "Determined by the actual certificate used" according to JSSE Standard Names, but in
         * practice trust managers only require the authType to be a non-null, non-empty String.
         */

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
            return "RSA";
        case SignatureAlgorithm.dsa:
            return "DSA";
        case SignatureAlgorithm.ecdsa:
            return "EC";
        case SignatureAlgorithm.ed25519:
            return "Ed25519";
        case SignatureAlgorithm.ed448:
            return "Ed448";
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            return "RSA";
        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return "RSASSA-PSS";
        default:
            throw new IllegalArgumentException();
        }
    }

    static String getAuthTypeServer(int keyExchangeAlgorithm)
    {
        /*
         * For use with checkServerTrusted calls on a trust manager.
         * "The key exchange algorithm portion of the cipher suites represented as a String [..]"
         * according to JSSE Standard Names.
         */

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_DSS:
            return "DH_DSS";
        case KeyExchangeAlgorithm.DH_RSA:
            return "DH_RSA";
        case KeyExchangeAlgorithm.DHE_DSS:
            return "DHE_DSS";
        case KeyExchangeAlgorithm.DHE_RSA:
            return "DHE_RSA";
        case KeyExchangeAlgorithm.ECDH_ECDSA:
            return "ECDH_ECDSA";
        case KeyExchangeAlgorithm.ECDH_RSA:
            return "ECDH_RSA";
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return "ECDHE_ECDSA";
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return "ECDHE_RSA";
        case KeyExchangeAlgorithm.NULL:
            // For compatibility with SunJSSE, use "UNKNOWN" for TLS 1.3 cipher suites.  
//            return "NULL";
            return "UNKNOWN";
        case KeyExchangeAlgorithm.RSA:
            // Prefixed to disambiguate from RSA signing credentials
            return "KE:RSA";
        case KeyExchangeAlgorithm.SRP_DSS:
            return "SRP_DSS";
        case KeyExchangeAlgorithm.SRP_RSA:
            return "SRP_RSA";
        default:
            throw new IllegalArgumentException();
        }
    }

    static Vector<X500Name> getCertificateAuthorities(BCX509ExtendedTrustManager x509TrustManager)
    {
        Set<X500Principal> caSubjects = new HashSet<X500Principal>();
        for (X509Certificate acceptedIssuer : x509TrustManager.getAcceptedIssuers())
        {
            if (acceptedIssuer.getBasicConstraints() >= 0)
            {
                caSubjects.add(acceptedIssuer.getSubjectX500Principal());
            }
            else
            {
                // Trusting a non-CA certificate, so include its issuer as a CA
                caSubjects.add(acceptedIssuer.getIssuerX500Principal());
            }
        }

        if (caSubjects.isEmpty())
        {
            return null;
        }

        /*
         * TODO[jsse] Destined for an extension, but what if there are too many? Extension has total
         * size limit, and some servers may limit e.g. ClientHello total size.
         */
        Vector<X500Name> certificateAuthorities = new Vector<X500Name>(caSubjects.size());
        for (X500Principal caSubject : caSubjects)
        {
            certificateAuthorities.add(X500Name.getInstance(caSubject.getEncoded()));
        }
        return certificateAuthorities;
    }

    static Certificate getCertificateMessage(JcaTlsCrypto crypto, X509Certificate[] chain)
    {
        if (chain == null || chain.length < 1)
        {
            throw new IllegalArgumentException();
        }

        TlsCertificate[] certificateList = new TlsCertificate[chain.length];
        for (int i = 0; i < chain.length; ++i)
        {
            certificateList[i] = new JcaTlsCertificate(crypto, chain[i]);
        }
        return new Certificate(certificateList);
    }

    static Certificate getCertificateMessage13(JcaTlsCrypto crypto, X509Certificate[] chain,
        byte[] certificateRequestContext)
    {
        if (chain == null || chain.length < 1)
        {
            throw new IllegalArgumentException();
        }

        CertificateEntry[] certificateEntryList = new CertificateEntry[chain.length];
        for (int i = 0; i < chain.length; ++i)
        {
            JcaTlsCertificate certificate = new JcaTlsCertificate(crypto, chain[i]);

            // TODO[tls13] Support various extensions
            Hashtable<Integer, byte[]> extensions = null;

            certificateEntryList[i] = new CertificateEntry(certificate, extensions);
        }

        return new Certificate(certificateRequestContext, certificateEntryList);
    }

    static X509Certificate getEndEntity(JcaTlsCrypto crypto, Certificate certificateMessage) throws IOException
    {
        if (certificateMessage == null || certificateMessage.isEmpty())
        {
            return null;
        }

        return getX509Certificate(crypto, certificateMessage.getCertificateAt(0));
    }

    static String getJcaSignatureAlgorithmBC(String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        if (!jcaSignatureAlgorithm.endsWith("withRSAandMGF1"))
        {
            return jcaSignatureAlgorithm;
        }

        return jcaSignatureAlgorithm + ":" + keyAlgorithm;
    }

    static String getKeyType(SignatureSchemeInfo signatureSchemeInfo)
    {
        return signatureSchemeInfo.getKeyAlgorithm();
    }

    static String getKeyTypeLegacyClient(short clientCertificateType)
    {
        switch (clientCertificateType)
        {
        /*
         * BCJSSE doesn't support any static key exchange cipher suites; any of these values would
         * be filtered out (as invalid) by the low-level TLS code.
         */
//        case ClientCertificateType.dss_fixed_dh:
//            return "DH_DSA";
//        case ClientCertificateType.ecdsa_fixed_ecdh:
//            return "EC_EC";
//        case ClientCertificateType.rsa_fixed_dh:
//            return "DH_RSA";
//        case ClientCertificateType.rsa_fixed_ecdh:
//            return "EC_RSA";

        case ClientCertificateType.dss_sign:
            return "DSA";
        case ClientCertificateType.ecdsa_sign:
            return "EC";
        case ClientCertificateType.rsa_sign:
            return "RSA";
        default:
            throw new IllegalArgumentException();
        }
    }

    static String getKeyTypeLegacyServer(int keyExchangeAlgorithm)
    {
        /*
         * For use with chooseServerAlias calls on a key manager. JSSE Standard Names suggest using
         * the same set of key types as getKeyTypeClient, but this doesn't give enough information
         * to the key manager, so we currently use the same names as getAuthTypeServer.
         */

        return getAuthTypeServer(keyExchangeAlgorithm);
    }

    static Vector<ProtocolName> getProtocolNames(String[] applicationProtocols)
    {
        if (null == applicationProtocols || applicationProtocols.length < 1)
        {
            return null;
        }

        Vector<ProtocolName> result = new Vector<ProtocolName>(applicationProtocols.length);
        for (String applicationProtocol : applicationProtocols)
        {
            result.add(ProtocolName.asUtf8Encoding(applicationProtocol));
        }
        return result;
    }

    static List<String> getProtocolNames(Vector<ProtocolName> applicationProtocols)
    {
        if (null == applicationProtocols || applicationProtocols.isEmpty())
        {
            return null;
        }

        ArrayList<String> result = new ArrayList<String>(applicationProtocols.size());
        for (ProtocolName applicationProtocol : applicationProtocols)
        {
            result.add(applicationProtocol.getUtf8Decoding());
        }
        return result;
    }

    static byte[] getStatusResponse(OCSPResponse ocspResponse) throws IOException
    {
        return null == ocspResponse ? TlsUtils.EMPTY_BYTES : ocspResponse.getEncoded(ASN1Encoding.DER);
    }

    static List<byte[]> getStatusResponses(CertificateStatus certificateStatus) throws IOException
    {
        if (null != certificateStatus)
        {
            switch (certificateStatus.getStatusType())
            {
            case CertificateStatusType.ocsp:
            {
                OCSPResponse ocspResponse = certificateStatus.getOCSPResponse();
                return Collections.singletonList(getStatusResponse(ocspResponse));
            }
            case CertificateStatusType.ocsp_multi:
            {
                @SuppressWarnings("unchecked")
                Vector<OCSPResponse> ocspResponseList = certificateStatus.getOCSPResponseList();
                int count = ocspResponseList.size();

                ArrayList<byte[]> statusResponses = new ArrayList<byte[]>(count);
                for (int i = 0; i < count; ++i)
                {
                    OCSPResponse ocspResponse = (OCSPResponse)ocspResponseList.elementAt(i);
                    statusResponses.add(getStatusResponse(ocspResponse));
                }

                return Collections.unmodifiableList(statusResponses);
            }
            }
        }
        return null;
    }

    static X500Principal[] getTrustedIssuers(Vector<TrustedAuthority> trustedCAKeys) throws IOException
    {
        if (null == trustedCAKeys || trustedCAKeys.isEmpty())
        {
            return null;
        }

        int count = trustedCAKeys.size();
        X500Principal[] principals = new X500Principal[count];
        for (int i = 0; i < count; ++i)
        {
            TrustedAuthority trustedAuthority = (TrustedAuthority)trustedCAKeys.get(i);
            if (IdentifierType.x509_name != trustedAuthority.getIdentifierType())
            {
                // TODO We currently only support the trusted_ca_keys extension if EVERY entry is an x509_name
                return null;
            }

            principals[i] = toX500Principal(trustedAuthority.getX509Name());
        }
        return principals;
    }

    static X509Certificate getX509Certificate(JcaTlsCrypto crypto, TlsCertificate tlsCertificate) throws IOException
    {
        return JcaTlsCertificate.convert(crypto, tlsCertificate).getX509Certificate();
    }

    static X509Certificate[] getX509CertificateChain(JcaTlsCrypto crypto, Certificate certificateMessage)
    {
        if (certificateMessage == null || certificateMessage.isEmpty())
        {
            return EMPTY_CHAIN;
        }

        try
        {
            X509Certificate[] chain = new X509Certificate[certificateMessage.getLength()];
            for (int i = 0; i < chain.length; ++i)
            {
                chain[i] = JcaTlsCertificate.convert(crypto, certificateMessage.getCertificateAt(i)).getX509Certificate();
            }
            return chain;
        }
        catch (IOException e)
        {
            // TODO[jsse] Logging
            throw new RuntimeException(e);
        }
    }

    static X509Certificate[] getX509CertificateChain(java.security.cert.Certificate[] chain)
    {
        if (chain == null)
        {
            return null;
        }
        if (chain instanceof X509Certificate[])
        {
            return JsseUtils.containsNull(chain) ? null : (X509Certificate[])chain;
        }
        X509Certificate[] x509Chain = new X509Certificate[chain.length];
        for (int i = 0; i < chain.length; ++i)
        {
            java.security.cert.Certificate c = chain[i];
            if (!(c instanceof X509Certificate))
            {
                return null;
            }
            x509Chain[i] = (X509Certificate)c;
        }
        return x509Chain;
    }

    static X500Principal getSubject(JcaTlsCrypto crypto, Certificate certificateMessage)
    {
        if (certificateMessage == null || certificateMessage.isEmpty())
        {
            return null;
        }

        try
        {
            return getX509Certificate(crypto, certificateMessage.getCertificateAt(0)).getSubjectX500Principal();
        }
        catch (IOException e)
        {
            // TODO[jsse] Logging
            throw new RuntimeException(e);
        }
    }

    static String getAlertLogMessage(String root, short alertLevel, short alertDescription)
    {
        return root + " " + AlertLevel.getText(alertLevel) + " " + AlertDescription.getText(alertDescription) + " alert";
    }

    static String getKeyAlgorithm(Key key)
    {
        if (key instanceof PrivateKey)
        {
            return getPrivateKeyAlgorithm((PrivateKey)key);
        }
        if (key instanceof PublicKey)
        {
            return getPublicKeyAlgorithm((PublicKey)key);
        }
        return key.getAlgorithm();
    }

    static String getPrivateKeyAlgorithm(PrivateKey privateKey)
    {
        String algorithm = privateKey.getAlgorithm();

        /*
         * TODO[fips] Early BCFIPS versions didn't return standard name for PSS keys. Once the
         * minimum BCFIPS version no longer has that problem, this handler can be removed.
         */
        if ("RSA".equalsIgnoreCase(algorithm))
        {
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(privateKey.getEncoded());
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(pki.getPrivateKeyAlgorithm().getAlgorithm()))
            {
                return "RSASSA-PSS";
            }
        }

        return algorithm;
    }

    static String getPublicKeyAlgorithm(PublicKey publicKey)
    {
        String algorithm = publicKey.getAlgorithm();

        /*
         * TODO[fips] Early BCFIPS versions didn't return standard name for PSS keys. Once the
         * minimum BCFIPS version no longer has that problem, this handler can be removed.
         */
        if ("RSA".equalsIgnoreCase(algorithm))
        {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(spki.getAlgorithm().getAlgorithm()))
            {
                return "RSASSA-PSS";
            }
        }

        return algorithm;
    }

    static boolean isNameSpecified(String name)
    {
        return null != name && name.length() > 0;
    }

    static boolean isTLSv12(String protocol)
    {
        ProtocolVersion protocolVersion = ProvSSLContextSpi.getProtocolVersion(protocol);

        return null != protocolVersion && TlsUtils.isTLSv12(protocolVersion); 
    }

    static boolean isUsableKeyForServer(short signatureAlgorithm, PrivateKey privateKey)
    {
        final String algorithm = getPrivateKeyAlgorithm(privateKey);

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.dsa:
            return privateKey instanceof DSAPrivateKey || "DSA".equalsIgnoreCase(algorithm);

        case SignatureAlgorithm.ecdsa:
            return privateKey instanceof ECPrivateKey || "EC".equalsIgnoreCase(algorithm);

        case SignatureAlgorithm.ed25519:
            return "Ed25519".equalsIgnoreCase(algorithm);

        case SignatureAlgorithm.ed448:
            return "Ed448".equalsIgnoreCase(algorithm);

        case SignatureAlgorithm.rsa:
            return "RSA".equalsIgnoreCase(algorithm);

        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            return "RSA".equalsIgnoreCase(algorithm);

        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return "RSASSA-PSS".equalsIgnoreCase(algorithm);

        default:
            return false;
        }
    }

    static boolean isUsableKeyForServerLegacy(int keyExchangeAlgorithm, PrivateKey privateKey)
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return isUsableKeyForServer(TlsUtils.getLegacySignatureAlgorithmServer(keyExchangeAlgorithm), privateKey);

        case KeyExchangeAlgorithm.RSA:
            return "RSA".equalsIgnoreCase(getPrivateKeyAlgorithm(privateKey));

        // NOTE: This method should never be called for TLS 1.3 
        case KeyExchangeAlgorithm.NULL:
        default:
            return false;
        }
    }

    static X500Principal toX500Principal(X500Name name) throws IOException
    {
        return null == name ? null : new X500Principal(name.getEncoded(ASN1Encoding.DER));
    }

    static X500Principal[] toX500Principals(Vector<X500Name> names) throws IOException
    {
        if (null == names)
        {
            return null;
        }

        Set<X500Principal> principals = new LinkedHashSet<X500Principal>();

        int count = names.size();
        for (int i = 0; i < count; ++i)
        {
            X500Principal principal = toX500Principal(names.get(i));
            if (null != principal)
            {
                principals.add(principal);
            }
        }

        return principals.toArray(new X500Principal[0]);
    }

    static BCSNIServerName convertSNIServerName(ServerName serverName)
    {
        short nameType = serverName.getNameType();
        byte[] nameData = serverName.getNameData();

        switch (nameType)
        {
        case BCStandardConstants.SNI_HOST_NAME:
            return new BCSNIHostName(nameData);
        default:
            return new BCUnknownServerName(nameType, nameData);
        }
    }

    static List<BCSNIServerName> convertSNIServerNames(Vector<ServerName> serverNameList)
    {
        if (null == serverNameList || serverNameList.isEmpty())
        {
            return Collections.emptyList();
        }

        ArrayList<BCSNIServerName> result = new ArrayList<BCSNIServerName>(serverNameList.size());

        Enumeration<ServerName> serverNames = serverNameList.elements();
        while (serverNames.hasMoreElements())
        {
            result.add(convertSNIServerName(serverNames.nextElement()));
        }

        return Collections.unmodifiableList(result);
    }

    static BCSNIServerName findMatchingSNIServerName(Vector<ServerName> serverNameList,
        Collection<BCSNIMatcher> sniMatchers)
    {
        if (!serverNameList.isEmpty())
        {
            List<BCSNIServerName> sniServerNames = convertSNIServerNames(serverNameList);
            for (BCSNIMatcher sniMatcher : sniMatchers)
            {
                if (null != sniMatcher)
                {
                    int nameType = sniMatcher.getType();
                    for (BCSNIServerName sniServerName : sniServerNames)
                    {
                        if (null == sniServerName || sniServerName.getType() != nameType)
                        {
                            continue;
                        }
                        if (sniMatcher.matches(sniServerName))
                        {
                            return sniServerName;
                        }
                        break;
                    }
                }
            }
        }

        return null;
    }

    static BCSNIHostName getSNIHostName(List<BCSNIServerName> serverNames)
    {
        if (null != serverNames)
        {
            for (BCSNIServerName serverName : serverNames)
            {
                if (null != serverName && BCStandardConstants.SNI_HOST_NAME == serverName.getType())
                {
                    if (serverName instanceof BCSNIHostName)
                    {
                        return (BCSNIHostName)serverName;
                    }

                    try
                    {
                        return new BCSNIHostName(serverName.getEncoded());
                    }
                    catch (RuntimeException e)
                    {
                        return null;
                    }
                }
            }
        }
        return null;
    }

    static boolean requireCloseNotify()
    {
        return provRequireCloseNotify;
    }

    static String stripDoubleQuotes(String s)
    {
        return stripOuterChars(s, '"', '"');
    }

    static String stripSquareBrackets(String s)
    {
        return stripOuterChars(s, '[', ']');
    }

    private static String stripOuterChars(String s, char openChar, char closeChar)
    {
        if (s != null)
        {
            int sLast = s.length() - 1;
            if (sLast > 0 && s.charAt(0) == openChar && s.charAt(sLast) == closeChar)
            {
                return s.substring(1, sLast);
            }
        }
        return s;
    }

    static boolean useExtendedMasterSecret()
    {
        return provTlsUseExtendedMasterSecret;
    }
}
