package org.bouncycastle.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint;
import org.bouncycastle.crypto.constraints.QuantumVulnerableConstraint;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoServiceConstraintsTest
    extends TestCase
{
    // every test passes its own provider instance, built under the constraint it sets, and the
    // installed "BC" is left alone so the rest of the suite is unaffected
    public void tearDown()
    {
        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    public String getName()
    {
        return "CryptoServiceConstraintsTest";
    }

    public void test112bits()
        throws Exception
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(112));

        try
        {
            Cipher.getInstance("ARC4", new BouncyCastleProvider());
            fail("no exception!");
        }
        catch (NoSuchAlgorithmException e)
        {
            assertEquals("No such algorithm: ARC4", e.getMessage());
        }

        try
        {
            Cipher.getInstance("DES", new BouncyCastleProvider());
            fail("no exception!");
        }
        catch (NoSuchAlgorithmException e)
        {
            assertEquals("No such algorithm: DES", e.getMessage());
        }

        Cipher.getInstance("DESede", new BouncyCastleProvider());

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    public void test128bits()
        throws Exception
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            Cipher.getInstance("DES", new BouncyCastleProvider());
            fail("no exception!");
        }
        catch (NoSuchAlgorithmException e)
        {
            assertEquals("No such algorithm: DES", e.getMessage());
        }

        try
        {
            Cipher.getInstance("DESede", new BouncyCastleProvider());
            fail("no exception!");
        }
        catch (NoSuchAlgorithmException e)
        {
            assertEquals("No such algorithm: DESede", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    /*
     * RSA and ECDSA signing is refused and verification allowed under legacyUseOnly(), both are
     * refused under rejectAll(), and ML-DSA and ML-KEM are unaffected by either.
     */
    public void testQuantumVulnerableSignatures()
        throws Exception
    {
        Provider bc = new BouncyCastleProvider();

        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", bc);
        rsaGen.initialize(2048);
        KeyPair rsaKp = rsaGen.generateKeyPair();
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", bc);
        ecGen.initialize(256);
        KeyPair ecKp = ecGen.generateKeyPair();
        byte[] rsaSig = sign(bc, "SHA256withRSA", rsaKp);
        byte[] ecSig = sign(bc, "SHA256withECDSA", ecKp);

        CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.legacyUseOnly());

        Provider legacy = new BouncyCastleProvider();

        expectSignRefused(legacy, "SHA256withRSA", rsaKp, "RSA");
        expectSignRefused(legacy, "SHA256withRSAandMGF1", rsaKp, "RSA");
        expectSignRefused(legacy, "SHA256withECDSA", ecKp, "ECDSA");

        assertTrue(verify(legacy, "SHA256withRSA", rsaKp, rsaSig));
        assertTrue(verify(legacy, "SHA256withECDSA", ecKp, ecSig));

        try
        {
            KeyPairGenerator.getInstance("RSA", legacy);
            fail("RSA key generation not refused");
        }
        catch (NoSuchAlgorithmException e)
        {
            assertEquals("quantum-vulnerable service RSAKeyGen is disallowed for KEYGEN", e.getCause().getMessage());
        }

        checkPostQuantum(legacy);

        CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.rejectAll());

        Provider reject = new BouncyCastleProvider();

        expectSignRefused(reject, "SHA256withRSA", rsaKp, "RSA");
        expectSignRefused(reject, "SHA256withECDSA", ecKp, "ECDSA");
        expectVerifyRefused(reject, "SHA256withRSA", rsaKp, "RSA");
        expectVerifyRefused(reject, "SHA256withECDSA", ecKp, "ECDSA");

        checkPostQuantum(reject);
    }

    private void checkPostQuantum(Provider provider)
        throws Exception
    {
        KeyPair dsaKp = KeyPairGenerator.getInstance("ML-DSA", provider).generateKeyPair();
        assertTrue(verify(provider, "ML-DSA", dsaKp, sign(provider, "ML-DSA", dsaKp)));

        KeyPair kemKp = KeyPairGenerator.getInstance("ML-KEM", provider).generateKeyPair();
        KeyGenerator kemGen = KeyGenerator.getInstance("ML-KEM", provider);
        kemGen.init(new KEMGenerateSpec(kemKp.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)kemGen.generateKey();
        kemGen.init(new KEMExtractSpec(kemKp.getPrivate(), encapsulated.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation extracted = (SecretKeyWithEncapsulation)kemGen.generateKey();
        assertTrue(org.bouncycastle.util.Arrays.areEqual(encapsulated.getEncoded(), extracted.getEncoded()));
    }

    private static void expectSignRefused(Provider provider, String algorithm, KeyPair kp, String service)
        throws Exception
    {
        Signature signature = Signature.getInstance(algorithm, provider);
        try
        {
            signature.initSign(kp.getPrivate());
            fail(algorithm + " signing not refused");
        }
        catch (CryptoServiceConstraintsException e)
        {
            assertEquals("quantum-vulnerable service " + service + " is disallowed for SIGNING", e.getMessage());
        }
    }

    private static void expectVerifyRefused(Provider provider, String algorithm, KeyPair kp, String service)
        throws Exception
    {
        Signature signature = Signature.getInstance(algorithm, provider);
        try
        {
            signature.initVerify(kp.getPublic());
            fail(algorithm + " verification not refused");
        }
        catch (CryptoServiceConstraintsException e)
        {
            assertEquals("quantum-vulnerable service " + service + " is disallowed for VERIFYING", e.getMessage());
        }
    }

    private static byte[] sign(Provider provider, String algorithm, KeyPair kp)
        throws Exception
    {
        Signature signature = Signature.getInstance(algorithm, provider);
        signature.initSign(kp.getPrivate());
        signature.update(new byte[32]);
        return signature.sign();
    }

    private static boolean verify(Provider provider, String algorithm, KeyPair kp, byte[] sig)
        throws Exception
    {
        Signature signature = Signature.getInstance(algorithm, provider);
        signature.initVerify(kp.getPublic());
        signature.update(new byte[32]);
        return signature.verify(sig);
    }}
