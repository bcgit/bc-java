package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.internal.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KEM tests for the standardised FrodoKEM (ISO/IEC 18033-2) with the BC provider.
 */
public class FrodoKEMTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKeyPairGenAndFactory()
        throws Exception
    {
        FrodoKEMParameterSpec[] specs = new FrodoKEMParameterSpec[]{
            FrodoKEMParameterSpec.frodokem976shake,
            FrodoKEMParameterSpec.frodokem1344shake,
            FrodoKEMParameterSpec.efrodokem976shake,
            FrodoKEMParameterSpec.efrodokem1344shake,
            FrodoKEMParameterSpec.frodokem976aes,
            FrodoKEMParameterSpec.frodokem1344aes,
            FrodoKEMParameterSpec.efrodokem976aes,
            FrodoKEMParameterSpec.efrodokem1344aes
        };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
            kpg.initialize(specs[i], new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("FRODOKEM", "BC");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

            assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), pub.getEncoded()));
            assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), priv.getEncoded()));
            assertEquals(specs[i].getName(), kp.getPublic().getAlgorithm());
        }
    }

    public void testBasicKEM()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "FRODOKEM", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "FRODOKEM", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(FrodoKEMParameterSpec.efrodokem1344shake, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "FRODOKEM", new KEMParameterSpec("AES"));
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KEMParameterSpec ktsParameterSpec)
        throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BC");

        byte[] keyBytes;
        if (algorithm.endsWith("KWP"))
        {
            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0faa");
        }
        else
        {
            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        }
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        w1.init(Cipher.WRAP_MODE, kp.getPublic(), ktsParameterSpec);

        byte[] data = w1.wrap(key);

        Cipher w2 = Cipher.getInstance(algorithm, "BC");

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
    }

    public void testGenerateAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("FRODOKEM", "BC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        // KEMGenerateSpec(pub, "AES") applies the default KDF (X9.44 KDF-3 / SHA-256) at 256 bits,
        // so the derived AES key is 32 bytes regardless of frodokem976shake's 192-bit raw secret.
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    /**
     * The KEM cipher's data-encapsulation mechanism is caller-selectable; the non-AES wrap
     * algorithms the removed round-3 tests exercised have to keep working here too.
     */
    public void testKEMWrapAlgorithms()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        performKEMScipher(kp, "FRODOKEM", new KEMParameterSpec("Camellia"));
        performKEMScipher(kp, "FRODOKEM", new KEMParameterSpec("Camellia-KWP"));
        performKEMScipher(kp, "FRODOKEM", new KEMParameterSpec("SEED", 128));   // SEED keys are 128-bit only
        performKEMScipher(kp, "FRODOKEM", new KEMParameterSpec("ARIA"));
        performKEMScipher(kp, "FRODOKEM", new KEMParameterSpec("ARIA-KWP"));
    }

    /**
     * KeyFactory hands the encoded specs back through getKeySpec, the rebuilt keys are equal to
     * (not merely encoded like) the originals with matching hashCodes, and the ISO/IEC 18033-2
     * object identifier resolves as a KeyFactory name - what a caller dispatching on the OID in a
     * received encoding does.
     */
    public void testKeySpecsAndEquality()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("FRODOKEM", "BC");

        X509EncodedKeySpec pubSpec = (X509EncodedKeySpec)kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
        PKCS8EncodedKeySpec privSpec = (PKCS8EncodedKeySpec)kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
        assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), pubSpec.getEncoded()));
        assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), privSpec.getEncoded()));

        PublicKey pub = kf.generatePublic(pubSpec);
        PrivateKey priv = kf.generatePrivate(privSpec);
        assertEquals(kp.getPublic(), pub);
        assertEquals(kp.getPublic().hashCode(), pub.hashCode());
        assertEquals(kp.getPrivate(), priv);
        assertEquals(kp.getPrivate().hashCode(), priv.hashCode());

        KeyFactory oidKf = KeyFactory.getInstance(ISOIECObjectIdentifiers.frodokem976_shake.getId(), "BC");
        assertEquals(kp.getPublic(), oidKf.generatePublic(pubSpec));
    }

    /**
     * The parameter-set named Cipher and KeyGenerator services are locked to their set: a key of
     * that set works, a key of any other set is refused - the import-policy property the named
     * KeyFactory sweep asserts, applied to the KEM operations.
     */
    public void testParameterSetLocks()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        kpg.initialize(FrodoKEMParameterSpec.efrodokem976shake, new SecureRandom());
        KeyPair other = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance("frodokem976shake", "BC");
        cipher.init(Cipher.WRAP_MODE, kp.getPublic(), new SecureRandom());
        byte[] wrapped = cipher.wrap(new SecretKeySpec(new byte[16], "AES"));
        cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        try
        {
            cipher.init(Cipher.WRAP_MODE, other.getPublic(), new SecureRandom());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("cipher locked to frodokem976shake", e.getMessage());
        }
        try
        {
            cipher.init(Cipher.UNWRAP_MODE, other.getPrivate());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("cipher locked to frodokem976shake", e.getMessage());
        }

        KeyGenerator keyGen = KeyGenerator.getInstance("frodokem976shake", "BC");
        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
        try
        {
            keyGen.init(new KEMGenerateSpec(other.getPublic(), "AES"), new SecureRandom());
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key generator locked to frodokem976shake", e.getMessage());
        }
        try
        {
            keyGen.init(new KEMExtractSpec(other.getPrivate(), secEnc1.getEncapsulation(), "AES"));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key generator locked to frodokem976shake", e.getMessage());
        }
    }
}
