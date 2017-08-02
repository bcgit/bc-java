package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Vector;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentialedAgreement;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedAgreement;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedAgreement;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class TlsTestUtils
{
    static final byte[] rsaCertData = Base64
        .decode("MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2"
            + "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq"
            + "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA2MDIwNVoXDTEzMDIyNT"
            + "A2MDM0NVowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw"
            + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG"
            + "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy"
            + "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCBSAwEgYDVR"
            + "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAHU55Ncz"
            + "eglREcTg54YLUlGWu2WOYWhit/iM1eeq8Kivro7q98eW52jTuMI3CI5ulqd0hYzshQKQaZ5GDzErMyM=");

    static final byte[] dudRsaCertData = Base64
        .decode("MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2"
            + "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq"
            + "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA1NDcyOFoXDTEzMDIyNT"
            + "A1NDkwOFowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw"
            + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG"
            + "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy"
            + "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCAAEwEgYDVR"
            + "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAJg55PBS"
            + "weg6obRUKF4FF6fCrWFi6oCYSQ99LWcAeupc5BofW5MstFMhCOaEucuGVqunwT5G7/DweazzCIrSzB0=");

    static String fingerprint(org.bouncycastle.asn1.x509.Certificate c)
        throws IOException
    {
        byte[] der = c.getEncoded();
        byte[] sha1 = sha256DigestOf(der);
        byte[] hexBytes = Hex.encode(sha1);
        String hex = new String(hexBytes, "ASCII").toUpperCase();

        StringBuffer fp = new StringBuffer();
        int i = 0;
        fp.append(hex.substring(i, i + 2));
        while ((i += 2) < hex.length())
        {
            fp.append(':');
            fp.append(hex.substring(i, i + 2));
        }
        return fp.toString();
    }

    static byte[] sha256DigestOf(byte[] input)
    {
        SHA256Digest d = new SHA256Digest();
        d.update(input, 0, input.length);
        byte[] result = new byte[d.getDigestSize()];
        d.doFinal(result, 0);
        return result;
    }

    static String getCACertResource(short signatureAlgorithm) throws IOException
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.dsa:
            return "x509-ca-dsa.pem";
        case SignatureAlgorithm.ecdsa:
            return "x509-ca-ecdsa.pem";
        case SignatureAlgorithm.rsa:
            return "x509-ca-rsa.pem";
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    static TlsCredentialedAgreement loadAgreementCredentials(TlsContext context, String[] certResources,
        String keyResource) throws IOException
    {
        TlsCrypto crypto = context.getCrypto();
        Certificate certificate = loadCertificateChain(crypto, certResources);

        // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
        if (crypto instanceof BcTlsCrypto)
        {
            AsymmetricKeyParameter privateKey = loadBcPrivateKeyResource(keyResource);

            return new BcDefaultTlsCredentialedAgreement((BcTlsCrypto)context.getCrypto(), certificate, privateKey);
        }
        else
        {
            PrivateKey privateKey = loadJcaPrivateKeyResource(keyResource);

            return new JceDefaultTlsCredentialedAgreement((JcaTlsCrypto)context.getCrypto(), certificate, privateKey);
        }
    }

    static TlsCredentialedDecryptor loadEncryptionCredentials(TlsContext context, String[] certResources,
        String keyResource) throws IOException
    {
        TlsCrypto crypto = context.getCrypto();
        Certificate certificate = loadCertificateChain(crypto, certResources);

        // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
        if (crypto instanceof BcTlsCrypto)
        {
            AsymmetricKeyParameter privateKey = loadBcPrivateKeyResource(keyResource);

            return new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)crypto, certificate, privateKey);
        }
        else
        {
            PrivateKey privateKey = loadJcaPrivateKeyResource(keyResource);

            return new JceDefaultTlsCredentialedDecryptor((JcaTlsCrypto)crypto, certificate, privateKey);
        }
    }

    static TlsCredentialedSigner loadSignerCredentials(TlsContext context, String[] certResources, String keyResource,
        SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException
    {
        TlsCrypto crypto = context.getCrypto();
        Certificate certificate = loadCertificateChain(crypto, certResources);

        // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
        if (crypto instanceof BcTlsCrypto)
        {
            AsymmetricKeyParameter privateKey = loadBcPrivateKeyResource(keyResource);

            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), (BcTlsCrypto)crypto, privateKey, certificate, signatureAndHashAlgorithm);
        }
        else
        {
            PrivateKey privateKey = loadJcaPrivateKeyResource(keyResource);

            return new JcaDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), (JcaTlsCrypto)crypto, privateKey, certificate, signatureAndHashAlgorithm);
        }
    }

    static TlsCredentialedSigner loadSignerCredentials(TlsContext context, Vector supportedSignatureAlgorithms,
        short signatureAlgorithm, String certResource, String keyResource) throws IOException
    {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        if (supportedSignatureAlgorithms == null)
        {
            supportedSignatureAlgorithms = TlsUtils.getDefaultSignatureAlgorithms(signatureAlgorithm);
        }

        for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
        {
            SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm)
                supportedSignatureAlgorithms.elementAt(i);
            if (alg.getSignature() == signatureAlgorithm)
            {
                // Just grab the first one we find
                signatureAndHashAlgorithm = alg;
                break;
            }
        }

        if (signatureAndHashAlgorithm == null)
        {
            return null;
        }

        return loadSignerCredentials(context, new String[]{ certResource, getCACertResource(signatureAlgorithm) },
            keyResource, signatureAndHashAlgorithm);
    }

    static Certificate loadCertificateChain(TlsCrypto crypto, String[] resources)
        throws IOException
    {
        TlsCertificate[] chain = new TlsCertificate[resources.length];
        for (int i = 0; i < resources.length; ++i)
        {
            chain[i] = loadCertificateResource(crypto, resources[i]);
        }
        return new Certificate(chain);
    }

    static org.bouncycastle.asn1.x509.Certificate loadBcCertificateResource(String resource)
        throws IOException
    {
        PemObject pem = loadPemResource(resource);
        if (pem.getType().endsWith("CERTIFICATE"))
        {
            return org.bouncycastle.asn1.x509.Certificate.getInstance(pem.getContent());
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
    }

    static TlsCertificate loadCertificateResource(TlsCrypto crypto, String resource)
        throws IOException
    {
        PemObject pem = loadPemResource(resource);
        if (pem.getType().endsWith("CERTIFICATE"))
        {
            return crypto.createCertificate(pem.getContent());
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
    }

    static AsymmetricKeyParameter loadBcPrivateKeyResource(String resource)
        throws IOException
    {
        PemObject pem = loadPemResource(resource);
        if (pem.getType().equals("PRIVATE KEY"))
        {
            return PrivateKeyFactory.createKey(pem.getContent());
        }
        if (pem.getType().equals("ENCRYPTED PRIVATE KEY"))
        {
            throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");
        }
        if (pem.getType().equals("RSA PRIVATE KEY"))
        {
            RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
            return new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(),
                rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(),
                rsa.getExponent2(), rsa.getCoefficient());
        }
        if (pem.getType().equals("EC PRIVATE KEY"))
        {
            ECPrivateKey pKey = ECPrivateKey.getInstance(pem.getContent());
            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParameters());
            PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
            return PrivateKeyFactory.createKey(privInfo);
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid private key");
    }

    static PrivateKey loadJcaPrivateKeyResource(String resource)
        throws IOException
    {
        Throwable cause = null;
        try
        {
            PemObject pem = loadPemResource(resource);
            if (pem.getType().equals("PRIVATE KEY"))
            {
                return loadJcaPkcs8PrivateKey(pem.getContent());
            }
            if (pem.getType().equals("ENCRYPTED PRIVATE KEY"))
            {
                throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");
            }
            if (pem.getType().equals("RSA PRIVATE KEY"))
            {
                RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
                    KeyFactory keyFact = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                    return keyFact.generatePrivate(new RSAPrivateCrtKeySpec(rsa.getModulus(), rsa.getPublicExponent(),
                        rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(),
                        rsa.getExponent2(), rsa.getCoefficient()));
            }
        }
        catch (GeneralSecurityException e)
        {
            cause = e;
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid private key", cause);
    }

    static PrivateKey loadJcaPkcs8PrivateKey(byte[] encoded) throws GeneralSecurityException
    {
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(encoded);
        AlgorithmIdentifier algID = pki.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier oid = algID.getAlgorithm();

        String name;
        if (X9ObjectIdentifiers.id_dsa.equals(oid))
        {
            name = "DSA";
        }
        else if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid))
        {
            // TODO Try ECDH/ECDSA according to intended use?
            name = "EC";
        }
        else if (PKCSObjectIdentifiers.rsaEncryption.equals(oid))
        {
            name = "RSA";
        }
        else
        {
            name = oid.getId();
        }

        KeyFactory kf = KeyFactory.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    static PemObject loadPemResource(String resource)
        throws IOException
    {
        InputStream s = TlsTestUtils.class.getResourceAsStream(resource);
        PemReader p = new PemReader(new InputStreamReader(s));
        PemObject o = p.readPemObject();
        p.close();
        return o;
    }

    static boolean areSameCertificate(TlsCrypto crypto, TlsCertificate cert, String resource) throws IOException
    {
        // TODO Cache test resources?
        return areSameCertificate(cert, loadCertificateResource(crypto, resource));
    }

    static boolean areSameCertificate(TlsCertificate a, TlsCertificate b) throws IOException
    {
        // TODO[tls-ops] Support equals on TlsCertificate?
        return Arrays.areEqual(a.getEncoded(), b.getEncoded());
    }

    static boolean isCertificateOneOf(TlsCrypto crypto, TlsCertificate cert, String[] resources) throws IOException
    {
        for (int i = 0; i < resources.length; ++i)
        {
            if (areSameCertificate(crypto, cert, resources[i]))
            {
                return true;
            }
        }
        return false;
    }

    static TrustManagerFactory getSunX509TrustManagerFactory()
        throws NoSuchAlgorithmException
    {
        if (Security.getProvider("IBMJSSE2") != null)
        {
            return TrustManagerFactory.getInstance("IBMX509");
        }
        else
        {
            return TrustManagerFactory.getInstance("SunX509");
        }
    }

    static KeyManagerFactory getSunX509KeyManagerFactory()
        throws NoSuchAlgorithmException
    {
        if (Security.getProvider("IBMJSSE2") != null)
        {
            return KeyManagerFactory.getInstance("IBMX509");
        }
        else
        {
            return KeyManagerFactory.getInstance("SunX509");
        }
    }
}
