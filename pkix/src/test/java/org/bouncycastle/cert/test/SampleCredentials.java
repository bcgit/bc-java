package org.bouncycastle.cert.test;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class SampleCredentials
{
    public static final SampleCredentials ML_DSA_44 = load("ML-DSA-44", "pkix/cert/mldsa", "ML-DSA-44.pem");
    public static final SampleCredentials ML_DSA_65 = load("ML-DSA-65", "pkix/cert/mldsa", "ML-DSA-65.pem");
    public static final SampleCredentials ML_DSA_87 = load("ML-DSA-87", "pkix/cert/mldsa", "ML-DSA-87.pem");

    public static final SampleCredentials SLH_DSA_SHA2_128S = load("SLH-DSA-SHA2-128S", "pkix/cert/slhdsa",
        "SLH-DSA-SHA2-128S.pem");

    private static PemObject expectPemObject(PemReader pemReader, String type)
        throws IOException
    {
        PemObject result = pemReader.readPemObject();
        if (!type.equals(result.getType()))
        {
            throw new IllegalStateException();
        }
        return result;
    }

    private static SampleCredentials load(String algorithm, String path, String name)
    {
        try
        {
            if (Security.getProvider("BC") == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }

            InputStream input = new BufferedInputStream(TestResourceFinder.findTestResource(path, name));
            Reader reader = new InputStreamReader(input);

            PemReader pemReader = new PemReader(reader);
            PemObject pemPriv = expectPemObject(pemReader, "PRIVATE KEY");
            PemObject pemPub = expectPemObject(pemReader, "PUBLIC KEY");
            PemObject pemCert = expectPemObject(pemReader, "CERTIFICATE");
            pemReader.close();

            KeyFactory kf = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pemPriv.getContent()));
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(pemPub .getContent()));
            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            X509Certificate certificate = (X509Certificate)cf.generateCertificate(
                new ByteArrayInputStream(pemCert.getContent()));

            if (!publicKey.equals(certificate.getPublicKey()))
            {
                throw new IllegalStateException("public key mismatch");
            }

            return new SampleCredentials(keyPair, certificate);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    private final KeyPair keyPair;
    private final X509Certificate certificate;

    private SampleCredentials(KeyPair keyPair, X509Certificate certificate)
    {
        this.keyPair = keyPair;
        this.certificate = certificate;
    }

    public X509Certificate getCertificate()
    {
        return certificate;
    }

    public KeyPair getKeyPair()
    {
        return keyPair;
    }
}
