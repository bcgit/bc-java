package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Hashtable;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * Exercise the various key stores, making sure we at least get back what we put in!
 * <p>
 * This tests both the BKS, and the UBER key store.
 */
public class KeyStoreTest
    implements Test
{
    static char[]   passwd = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };

    public TestResult keyStoreTest(
        String    storeName)
    {
        try
        {
            KeyStore store = KeyStore.getInstance(storeName, "BC");

            store.load(null, null);

            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");

            gen.initialize(1024, new SecureRandom());

            KeyPair         pair = gen.generateKeyPair();
            RSAPrivateKey   privKey = (RSAPrivateKey)pair.getPrivate();
            RSAPublicKey    pubKey = (RSAPublicKey)pair.getPublic();
            BigInteger      modulus = privKey.getModulus();
            BigInteger      privateExponent = privKey.getPrivateExponent();
            

            //
            // distinguished name table.
            //
            Hashtable                   attrs = new Hashtable();

            attrs.put(X509Principal.C, "AU");
            attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
            attrs.put(X509Principal.L, "Melbourne");
            attrs.put(X509Principal.ST, "Victoria");
            attrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");

            //
            // extensions
            //

            //
            // create the certificate.
            //
            X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

            certGen.setSerialNumber(BigInteger.valueOf(1));
            certGen.setIssuerDN(new X509Principal(attrs));
            certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
            certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
            certGen.setSubjectDN(new X509Principal(attrs));
            certGen.setPublicKey(pubKey);
            certGen.setSignatureAlgorithm("MD5WithRSAEncryption");

            Certificate[]   chain = new Certificate[1];

            try
            {
                X509Certificate cert = certGen.generateX509Certificate(privKey);

                cert.checkValidity(new Date());

                cert.verify(pubKey);

                ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
                CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

                cert = (X509Certificate)fact.generateCertificate(bIn);

                chain[0] = cert;
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, getName() + ": error generating cert - " + e.toString());
            }

            store.setKeyEntry("private", privKey, passwd, chain);
            
            //
            // write out and read back store
            //
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            
            store.store(bOut, passwd);
            
            ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());

            //
            // start with a new key store
            //
            store = KeyStore.getInstance(storeName, "BC");

            store.load(bIn, passwd);
            
            //
            // verify public key
            //
            privKey = (RSAPrivateKey)store.getKey("private", passwd);
            
            if (!privKey.getModulus().equals(modulus))
            {
                return new SimpleTestResult(false, getName() + ": private key modulus wrong");
            }
            else if (!privKey.getPrivateExponent().equals(privateExponent))
            {
                return new SimpleTestResult(false, getName() + ": private key exponent wrong");
            }

            //
            // verify certificate
            //
            Certificate cert = store.getCertificateChain("private")[0];

            cert.verify(pubKey);

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public String getName()
    {
        return "KeyStore";
    }

    public TestResult perform()
    {
        TestResult  result = keyStoreTest("BKS");
        if (!result.isSuccessful())
        {
            return result;
        }

        result = keyStoreTest("UBER");

        if (!result.isSuccessful())
        {
            return result;
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new KeyStoreTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
