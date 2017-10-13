package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

import javax.crypto.interfaces.DHPrivateKey;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.NameType;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.ServerNameList;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

abstract class JsseUtils
{
    protected static X509Certificate[] EMPTY_CHAIN = new X509Certificate[0];

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

    public static String getAuthTypeClient(short clientCertificateType) throws IOException
    {
        switch (clientCertificateType)
        {
        case ClientCertificateType.dss_sign:
            return "DSA";
        case ClientCertificateType.ecdsa_sign:
            return "EC";
        case ClientCertificateType.rsa_sign:
            return "RSA";

        // TODO[jsse] "fixed" types and any others

        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static String getAuthTypeServer(int keyExchangeAlgorithm) throws IOException
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
            return "DH_anon";
        case KeyExchangeAlgorithm.DH_DSS:
            return "DH_DSS";
        case KeyExchangeAlgorithm.DH_RSA:
            return "DH_RSA";
        case KeyExchangeAlgorithm.DHE_DSS:
            return "DHE_DSS";
        case KeyExchangeAlgorithm.DHE_PSK:
            return "DHE_PSK";
        case KeyExchangeAlgorithm.DHE_RSA:
            return "DHE_RSA";
        case KeyExchangeAlgorithm.ECDH_anon:
            return "ECDH_anon";
        case KeyExchangeAlgorithm.ECDH_ECDSA:
            return "ECDH_ECDSA";
        case KeyExchangeAlgorithm.ECDH_RSA:
            return "ECDH_RSA";
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return "ECDHE_ECDSA";
        case KeyExchangeAlgorithm.ECDHE_PSK:
            return "ECDHE_PSK";
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return "ECDHE_RSA";
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

    static Vector getSupportedSignatureAlgorithms(TlsCrypto crypto)
    {
        short[] hashAlgorithms = new short[]{ HashAlgorithm.sha1, HashAlgorithm.sha224, HashAlgorithm.sha256,
            HashAlgorithm.sha384, HashAlgorithm.sha512 };
        short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.rsa, SignatureAlgorithm.ecdsa };

        Vector result = new Vector();
        for (int i = 0; i < signatureAlgorithms.length; ++i)
        {
            for (int j = 0; j < hashAlgorithms.length; ++j)
            {
                addIfSupported(crypto, result, new SignatureAndHashAlgorithm(hashAlgorithms[j], signatureAlgorithms[i]));
            }
        }

        // TODO Dynamically detect whether the TlsCrypto implementation can handle DSA2
        addIfSupported(crypto, result, new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.dsa));

        return result;
    }

    public static boolean isUsableKeyForServer(int keyExchangeAlgorithm, PrivateKey privateKey) throws IOException
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_DSS_EXPORT:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DH_RSA_EXPORT:
            return privateKey instanceof DHPrivateKey;

        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return privateKey instanceof ECPrivateKey;

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_DSS_EXPORT:
        case KeyExchangeAlgorithm.SRP_DSS:
            return privateKey instanceof DSAPrivateKey;

        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.DHE_RSA_EXPORT:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.RSA:
        case KeyExchangeAlgorithm.RSA_PSK:
        case KeyExchangeAlgorithm.SRP_RSA:
            return privateKey instanceof RSAPrivateKey;

        default:
            return false;
        }
    }

    static Set<X500Principal> toX500Principals(X500Name[] names) throws IOException
    {
        if (names == null || names.length == 0)
        {
            return Collections.emptySet();
        }

        Set<X500Principal> principals = new HashSet<X500Principal>(names.length);

        for (int i = 0; i < names.length; ++i)
        {
            X500Name name = names[i];
            if (name != null)
            {
            	principals.add(new X500Principal(name.getEncoded(ASN1Encoding.DER)));
            }
        }

        return principals;
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

    private static void addIfSupported(TlsCrypto crypto, Vector v, SignatureAndHashAlgorithm alg)
    {
        if (crypto.hasSignatureAndHashAlgorithm(alg))
        {
            v.addElement(alg);
        }
    }

    static Constructor getDeclaredConstructor(final Class clazz, final Class<?>... parameterTypes)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Constructor>()
        {
            public Constructor run()
            {
                try
                {
                    return clazz.getDeclaredConstructor(parameterTypes);
                }
                catch (Exception e)
                {
                    // ignore - maybe log?
                }

                return null;
            }
        });
    }

    static Class loadClass(Class sourceClass, final String className)
    {
        try
        {
            ClassLoader loader = sourceClass.getClassLoader();
            if (loader != null)
            {
                return loader.loadClass(className);
            }
            else
            {
                return AccessController.doPrivileged(new PrivilegedAction<Class>()
                {
                    public Class run()
                    {
                        try
                        {
                            return Class.forName(className);
                        }
                        catch (Exception e)
                        {
                            // ignore - maybe log?
                        }

                        return null;
                    }
                });
            }
        }
        catch (ClassNotFoundException e)
        {
            // ignore - maybe log?
        }

        return null;
    }

    static BCSNIServerName convertSNIServerName(ServerName serverName)
    {
        switch (serverName.getNameType())
        {
        case NameType.host_name:
            return new BCSNIHostName(serverName.getHostName());
        default:
            return null;
        }
    }

    static BCSNIServerName findMatchingSNIServerName(ServerNameList serverNameList,
        Collection<BCSNIMatcher> sniMatchers)
    {
        Enumeration serverNames = serverNameList.getServerNameList().elements();
        while (serverNames.hasMoreElements())
        {
            BCSNIServerName sniServerName = convertSNIServerName((ServerName)serverNames.nextElement());

            for (BCSNIMatcher sniMatcher : sniMatchers)
            {
                if (sniMatcher != null && sniMatcher.getType() == sniServerName.getType()
                    && sniMatcher.matches(sniServerName))
                {
                    return sniServerName;
                }
            }
        }
        return null;
    }

    static String stripQuotes(String s)
    {
        if (s != null)
        {
            int sLast = s.length() - 1;
            if (sLast > 0 && s.charAt(0) == '"' && s.charAt(sLast) == '"')
            {
                return s.substring(1, sLast);
            }
        }
        return s;
    }
}
