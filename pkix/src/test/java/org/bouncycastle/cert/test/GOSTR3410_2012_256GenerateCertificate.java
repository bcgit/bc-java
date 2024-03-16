package org.bouncycastle.cert.test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.time.ZonedDateTime;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.test.SimpleTest;

public class GOSTR3410_2012_256GenerateCertificate
    extends SimpleTest
{
    public static final String PARAMS = "Tc26-Gost-3410-12-256-paramSetB";
    public static final String SIGNATURE_ALGORITHM = "GOST3411WITHGOST3410-2012-256";
    private static final String ALGORITHM = "ECGOST3410-2012";
    
    public String getName()
    {
        return "GOSTR3410_2012_256GenerateCertificate";
    }

    public void performTest()
        throws Exception
    {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

            X509CertificateHolder certificate = generateSelfSignedCertificate();

            ASN1Sequence parameters =
                (ASN1Sequence)certificate.getSubjectPublicKeyInfo().getAlgorithm().getParameters();
        isEquals("Expected parameters size: 1, actual: " + parameters.size(), 1, parameters.size());
    }

    private static X509CertificateHolder generateSelfSignedCertificate()
    {
        try
        {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            keygen.initialize(new ECGenParameterSpec(PARAMS));

            KeyPair keyPair = keygen.generateKeyPair();

            X500Name subject = new X500Name("CN=TEST");
            X500Name issuer = subject;
            BigInteger serial = BigInteger.ONE;
            ZonedDateTime notBefore = ZonedDateTime.now();
            ZonedDateTime notAfter = notBefore.plusYears(1);

            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                Date.from(notBefore.toInstant()),
                Date.from(notAfter.toInstant()),
                subject,
                keyPair.getPublic()
            );
            ContentSigner contentSigner =
                new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate());

            return certificateBuilder.build(contentSigner);
        }
        catch (OperatorCreationException e)
        {
            System.out.println("Can not create certificate. " + e.getMessage());
            e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.printf("Algorithm %s is not found. %s\n", ALGORITHM, e.getMessage());
            e.printStackTrace();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            System.out.printf("Initialization parameter %s is not found for algorithm %s. %s\n", PARAMS, ALGORITHM,
                e.getMessage());
            e.printStackTrace();
        }
        catch (NoSuchProviderException e)
        {
            System.out.printf("Crypto provider BC is not found. %s\n", e.getMessage());
            e.printStackTrace();
        }

        return null;
    }

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new GOSTR3410_2012_256GenerateCertificate());
    }
}
