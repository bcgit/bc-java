package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCStandardConstants;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

abstract class JsseUtils
{
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

    static String[] copyOf(String[] data, int newLength)
    {
        String[] tmp = new String[newLength];
        System.arraycopy(data, 0, tmp, 0, Math.min(data.length, newLength));
        return tmp;
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

    static String getAuthTypeClient(short signatureAlgorithm) throws IOException
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
        // TODO[RFC 8422]
//        case SignatureAlgorithm.ed25519:
//            return "Ed25519";
//        case SignatureAlgorithm.ed448:
//            return "Ed448";
        // TODO[RFC 8446]
//        case SignatureAlgorithm.rsa_pss_rsae_sha256:
//        case SignatureAlgorithm.rsa_pss_rsae_sha384:
//        case SignatureAlgorithm.rsa_pss_rsae_sha512:
//            return "RSA_PSS_RSAE"; // TODO Review
//        case SignatureAlgorithm.rsa_pss_pss_sha256:
//        case SignatureAlgorithm.rsa_pss_pss_sha384:
//        case SignatureAlgorithm.rsa_pss_pss_sha512:
//            return "RSA_PSS_PSS"; // TODO Review
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    static String getAuthTypeServer(int keyExchangeAlgorithm) throws IOException
    {
        /*
         * For use with checkServerTrusted calls on a trust manager.
         * "The key exchange algorithm portion of the cipher suites represented as a String [..]"
         * according to JSSE Standard Names.
         */

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
            return "DH_anon";
        case KeyExchangeAlgorithm.DHE_DSS:
            return "DHE_DSS";
        case KeyExchangeAlgorithm.DHE_PSK:
            return "DHE_PSK";
        case KeyExchangeAlgorithm.DHE_RSA:
            return "DHE_RSA";
        case KeyExchangeAlgorithm.ECDH_anon:
            return "ECDH_anon";
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return "ECDHE_ECDSA";
        case KeyExchangeAlgorithm.ECDHE_PSK:
            return "ECDHE_PSK";
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return "ECDHE_RSA";
        case KeyExchangeAlgorithm.NULL:
            // For compatibility with SunJSSE, use "UNKNOWN" for TLS 1.3 cipher suites.  
//            return "NULL";
            return "UNKNOWN";
        case KeyExchangeAlgorithm.RSA:
            return "RSA";
        case KeyExchangeAlgorithm.RSA_PSK:
            return "RSA_PSK";
        case KeyExchangeAlgorithm.SRP:
            return "SRP";
        case KeyExchangeAlgorithm.SRP_DSS:
            return "SRP_DSS";
        case KeyExchangeAlgorithm.SRP_RSA:
            return "SRP_RSA";
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static Certificate getCertificateMessage(TlsCrypto crypto, X509Certificate[] chain) throws IOException
    {
        if (chain == null || chain.length < 1)
        {
            return Certificate.EMPTY_CHAIN;
        }

        TlsCertificate[] certificateList = new TlsCertificate[chain.length];
        try
        {
            for (int i = 0; i < chain.length; ++i)
            {
                // TODO[jsse] Prefer an option that will not re-encode for typical use-cases
                certificateList[i] = crypto.createCertificate(chain[i].getEncoded());
            }
        }
        catch (CertificateEncodingException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        return new Certificate(certificateList);
    }

    static String getKeyTypeClient(short clientCertificateType) throws IOException
    {
        /*
         * For use with chooseClientAlias calls on a key manager. Values from JSSE Standard Names.
         * 
         * TODO[RFC 8446] "RSASSA-PSS" is listed in JSSE Standard Names - how does that work?
         */

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
        // NOTE: Compatible with peer signature_algorithms "ed25519" and "ed448" in TLS 1.2
        case ClientCertificateType.ecdsa_sign:
            return "EC";
        // NOTE: (Presumably) compatible with peer signature_algorithms "rsa_pss_*" in TLS 1.2 
        case ClientCertificateType.rsa_sign:
            return "RSA";
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    static String getKeyTypeServer(int keyExchangeAlgorithm) throws IOException
    {
        /*
         * For use with chooseServerAlias calls on a key manager. JSSE Standard Names suggest using
         * the same set of key types as getKeyTypeClient, but this doesn't give enough information
         * to the key manager, so we currently use the same names as getAuthTypeServer.
         */

        return getAuthTypeServer(keyExchangeAlgorithm);
    }

    public static Vector getProtocolNames(String[] applicationProtocols)
    {
        if (null == applicationProtocols || applicationProtocols.length < 1)
        {
            return null;
        }

        Vector protocolNames = new Vector(applicationProtocols.length);
        for (String applicationProtocol : applicationProtocols)
        {
            protocolNames.addElement(ProtocolName.asUtf8Encoding(applicationProtocol));
        }
        return protocolNames;
    }

    public static List<String> getProtocolNames(Vector applicationProtocols)
    {
        if (null == applicationProtocols || applicationProtocols.isEmpty())
        {
            return null;
        }

        ArrayList<String> protocolNames = new ArrayList<String>(applicationProtocols.size());
        for (int i = 0; i < applicationProtocols.size(); ++i)
        {
            ProtocolName protocolName = (ProtocolName)applicationProtocols.elementAt(i);
            protocolNames .add(protocolName.getUtf8Decoding());
        }
        return protocolNames;
    }

    public static X509Certificate[] getX509CertificateChain(TlsCrypto crypto, Certificate certificateMessage)
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
                chain[i] = JcaTlsCertificate.convert((JcaTlsCrypto)crypto, certificateMessage.getCertificateAt(i)).getX509Certificate();
            }
            return chain;
        }
        catch (IOException e)
        {
            // TODO[jsse] Logging
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate[] getX509CertificateChain(java.security.cert.Certificate[] chain)
    {
        if (chain == null)
        {
            return null;
        }
        if (chain instanceof X509Certificate[])
        {
            return (X509Certificate[])chain;
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

    public static X500Principal getSubject(TlsCrypto crypto, Certificate certificateMessage)
    {
        if (certificateMessage == null || certificateMessage.isEmpty())
        {
            return null;
        }

        try
        {
            return JcaTlsCertificate.convert((JcaTlsCrypto)crypto, certificateMessage.getCertificateAt(0)).getX509Certificate()
                .getSubjectX500Principal();
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

    static boolean isTLSv12(String protocol)
    {
        ProtocolVersion protocolVersion = ProvSSLContextSpi.getProtocolVersion(protocol);

        return null != protocolVersion && TlsUtils.isTLSv12(protocolVersion); 
    }

    public static boolean isUsableKeyForServer(int keyExchangeAlgorithm, PrivateKey privateKey) throws IOException
    {
        if (privateKey == null)
        {
            return false;
        }

        String algorithm = privateKey.getAlgorithm();
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return privateKey instanceof ECPrivateKey || "EC".equals(algorithm);

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.SRP_DSS:
            return privateKey instanceof DSAPrivateKey || "DSA".equals(algorithm);

        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.RSA:
        case KeyExchangeAlgorithm.RSA_PSK:
        case KeyExchangeAlgorithm.SRP_RSA:
            return privateKey instanceof RSAPrivateKey || "RSA".equals(algorithm);

        case KeyExchangeAlgorithm.NULL:
            // TODO[tls13] Consider whether any checks needed here  
            return true;

        default:
            return false;
        }
    }

    static X500Principal[] toX500Principals(Vector<X500Name> names) throws IOException
    {
        if (null == names || names.isEmpty())
        {
            return null;
        }

        Set<X500Principal> principals = new LinkedHashSet<X500Principal>();

        int count = names.size();
        for (int i = 0; i < count; ++i)
        {
            X500Name name = names.elementAt(i);
            if (null != name)
            {
                principals.add(new X500Principal(name.getEncoded(ASN1Encoding.DER)));
            }
        }

        return principals.toArray(new X500Principal[0]);
    }

    static X500Name toX500Name(Principal principal)
    {
        if (principal == null)
        {
            return null;
        }
        else if (principal instanceof X500Principal)
        {
            return X500Name.getInstance(((X500Principal)principal).getEncoded());
        }
        else
        {
            // TODO[jsse] Should we really be trying to support these?
            return new X500Name(principal.getName());       // hope for the best
        }
    }

    static Set<X500Name> toX500Names(Principal[] principals)
    {
        if (principals == null || principals.length == 0)
        {
            return Collections.emptySet();
        }

        Set<X500Name> names = new HashSet<X500Name>(principals.length);

        for (int i = 0; i != principals.length; i++)
        {
            X500Name name = toX500Name(principals[i]);
            if (name != null)
            {
                names.add(name);
            }
        }

        return names;
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

    static List<BCSNIServerName> convertSNIServerNames(Vector serverNameList)
    {
        if (null == serverNameList || serverNameList.isEmpty())
        {
            return Collections.emptyList();
        }

        ArrayList<BCSNIServerName> result = new ArrayList<BCSNIServerName>(serverNameList.size());

        Enumeration serverNames = serverNameList.elements();
        while (serverNames.hasMoreElements())
        {
            result.add(convertSNIServerName((ServerName)serverNames.nextElement()));
        }

        return Collections.unmodifiableList(result);
    }

    static BCSNIServerName findMatchingSNIServerName(Vector serverNameList, Collection<BCSNIMatcher> sniMatchers)
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
