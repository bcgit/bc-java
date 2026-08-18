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
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KEM tests for the standardised Classic McEliece KEM (ISO/IEC 18033-2:2006/Amd 2:2026, Clause 13)
 * with the BC provider.
 */
public class CMCEKEMTest
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
        CMCEParameterSpec[] specs = new CMCEParameterSpec[]{
            CMCEParameterSpec.mceliece460896, CMCEParameterSpec.mceliece460896f,
            CMCEParameterSpec.mceliece460896pc, CMCEParameterSpec.mceliece460896pcf,
            CMCEParameterSpec.mceliece6688128, CMCEParameterSpec.mceliece6688128f,
            CMCEParameterSpec.mceliece6688128pc, CMCEParameterSpec.mceliece6688128pcf,
            CMCEParameterSpec.mceliece6960119, CMCEParameterSpec.mceliece6960119f,
            CMCEParameterSpec.mceliece6960119pc, CMCEParameterSpec.mceliece6960119pcf,
            CMCEParameterSpec.mceliece8192128, CMCEParameterSpec.mceliece8192128f,
            CMCEParameterSpec.mceliece8192128pc, CMCEParameterSpec.mceliece8192128pcf
        };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
            kpg.initialize(specs[i], new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("CMCE", "BC");
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");

        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(CMCEParameterSpec.mceliece460896pc, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES"));
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KEMParameterSpec ktsParameterSpec)
        throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BC");
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("CMCE", "BC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        assertEquals("AES", secEnc1.getAlgorithm());

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    /**
     * The no-KDF key size check is not a FrodoKEM speciality - it lives in the shared KdfUtil, so
     * every KEM KeyGenerator gets it. CMCE's secret is 256 bits, which covers the conventional
     * request but not one above it.
     */
    public void testNoKdfRejectsKeySizeAboveSharedSecret()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("CMCE", "BC");

        keyGen.init(new KEMGenerateSpec.Builder(kp.getPublic(), "AES", 256).withNoKdf().build(), new SecureRandom());

        assertEquals(32, keyGen.generateKey().getEncoded().length);

        keyGen.init(new KEMGenerateSpec.Builder(kp.getPublic(), "AES", 512).withNoKdf().build(), new SecureRandom());

        try
        {
            keyGen.generateKey();
            fail("no exception on over-long no-KDF generate");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("no KDF specified and the shared secret is 256 bits, 512 requested", e.getMessage());
        }
    }

    /**
     * The KEM cipher's data-encapsulation mechanism is caller-selectable; the non-AES wrap
     * algorithms the removed round-3 tests exercised have to keep working here too.
     */
    public void testKEMWrapAlgorithms()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        performKEMScipher(kp, "CMCE", new KEMParameterSpec("Camellia"));
        performKEMScipher(kp, "CMCE", new KEMParameterSpec("Camellia-KWP"));
        performKEMScipher(kp, "CMCE", new KEMParameterSpec("SEED", 128));   // SEED keys are 128-bit only
        performKEMScipher(kp, "CMCE", new KEMParameterSpec("ARIA"));
        performKEMScipher(kp, "CMCE", new KEMParameterSpec("ARIA-KWP"));
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("CMCE", "BC");

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

        KeyFactory oidKf = KeyFactory.getInstance(ISOIECObjectIdentifiers.mceliece460896.getId(), "BC");
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        kpg.initialize(CMCEParameterSpec.mceliece460896pc, new SecureRandom());
        KeyPair other = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance("mceliece460896", "BC");
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
            assertEquals("cipher locked to mceliece460896", e.getMessage());
        }
        try
        {
            cipher.init(Cipher.UNWRAP_MODE, other.getPrivate());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("cipher locked to mceliece460896", e.getMessage());
        }

        KeyGenerator keyGen = KeyGenerator.getInstance("mceliece460896", "BC");
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
            assertEquals("key generator locked to mceliece460896", e.getMessage());
        }
        try
        {
            keyGen.init(new KEMExtractSpec(other.getPrivate(), secEnc1.getEncapsulation(), "AES"));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key generator locked to mceliece460896", e.getMessage());
        }
    }
}
