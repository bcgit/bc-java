package org.bouncycastle.cert.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.cert.DeltaCertificateTool;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.encoders.Base64;

public class DeltaCertTest
    extends TestCase
{
    private static byte[] baseCertData = Base64.decode(
        "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");

    private static byte[] extracted = Base64.decode(
        "MIIBpzCCAU2gAwIBAgIUO4OXFstxvJOYP/07C37ulcODK88wCgYIKoZIzj0E"
      + "AwIwITEfMB0GA1UECAwWMS4yLjg0MC4xMDA0NS4yLjEgUm9vdDAeFw0yMzA0"
      + "MTIwMDAwMDBaFw0yNDA0MDYyMzU5NTlaMCExHzAdBgNVBAgMFjEuMi44NDAu"
      + "MTAwNDUuMi4xIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQt59pm"
      + "AR8kYICA8KkPpdqgwGQZuMXxYVKBsrr5/Bx6aOBLgS38UJoAD2vOM576akBt"
      + "IvZrN4/3QlvAz1wJ1kOuo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB"
      + "/wQEAwIBhjAfBgNVHSMEGDAWgBQy1HS2PIl0zKxGRhAZjHu1/Yzn2zAdBgNV"
      + "HQ4EFgQUMtR0tjyJdMysRkYQGYx7tf2M59swCgYIKoZIzj0EAwIDSAAwRQIg"
      + "EEk3DAMtJy/UBT0GqXvKLLmrfnKrlSNUz0GLuLsjiw0CIQCTQfyJ2eQLZJ0p"
      + "AWD9GAsPcw4HfoXCMwIJLTZL0OVX3g==");

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testDeltaExtract()
        throws Exception
    {
        X509CertificateHolder baseCert = new X509CertificateHolder(baseCertData);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BCPQC").build(baseCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder extCert = new X509CertificateHolder(extracted);

        assertTrue(extCert.equals(deltaCert));
    }

    public static void main(String[] args)
            throws Exception
        {
            Security.addProvider(new BouncyCastleProvider());

            KeyPairGenerator kpgS = KeyPairGenerator.getInstance("EC", "SunEC");

            kpgS.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair kpS = kpgS.generateKeyPair();
    

            KeyPairGenerator kpgB = KeyPairGenerator.getInstance("EC", "BC");

            kpgB.initialize(new ECGenParameterSpec("P-256"));

            KeyPair kpB = kpgB.generateKeyPair();

            byte[] msg = new byte[1000];

            long start = System.currentTimeMillis();

            Signature s = Signature.getInstance("SHA256withECDSA", "SunEC");

            for (int i = 0; i != 5000; i++)
            {

                s.initSign(kpS.getPrivate());

                s.update(msg);

                byte[] sig = s.sign();

                s.initVerify(kpS.getPublic());

                s.update(msg);

                if (!s.verify(sig))  throw new RuntimeException();
            }

            long sunDiff = System.currentTimeMillis() - start;

            start = System.currentTimeMillis();

            s = Signature.getInstance("SHA256withECDSA", "BC");

            for (int i = 0; i != 5000; i++)
            {

                s.initSign(kpB.getPrivate());

                s.update(msg);

                byte[] sig = s.sign();

                s.initVerify(kpB.getPublic());

                s.update(msg);

                if (!s.verify(sig))  throw new RuntimeException();
            }

            long bcDiff = System.currentTimeMillis() - start;

            System.err.println("SunEC: " + sunDiff);
            System.err.println("bcDiff: " + bcDiff);
        }
}
