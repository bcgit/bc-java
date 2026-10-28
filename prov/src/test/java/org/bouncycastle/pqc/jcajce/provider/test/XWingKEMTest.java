package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.XWingPrivateKey;
import org.bouncycastle.jcajce.interfaces.XWingPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * JCA tests for X-Wing (draft-connolly-cfrg-xwing-kem-11): key generation and the X.509 / PKCS#8 encodings
 * of its Section 5.8, the KEM KeyGenerator bridge, the KTS Cipher, and the draft's Appendix C test vector
 * run through the provider.
 */
public class XWingKEMTest
    extends TestCase
{
    // draft-connolly-cfrg-xwing-kem-11 Appendix C, first vector (the seeds the lightweight XWingTest uses)
    private static final byte[] SEED = Hex.decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    private static final byte[] ESEED = Hex.decode("3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2");
    private static final byte[] SS = Hex.decode("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384");

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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X-WING", "BC");
        KeyPair kp = kpg.generateKeyPair();

        assertTrue(kp.getPublic() instanceof XWingPublicKey);
        assertTrue(kp.getPrivate() instanceof XWingPrivateKey);
        assertEquals("X-WING", kp.getPublic().getAlgorithm());
        assertEquals("X-WING", kp.getPrivate().getAlgorithm());
        assertEquals(1216, ((XWingPublicKey)kp.getPublic()).getPublicData().length);

        // draft 5.8: id-XWing, parameters absent, raw public key bits, raw 32-byte seed
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        assertEquals(BCObjectIdentifiers.xwing, spki.getAlgorithm().getAlgorithm());
        assertNull(spki.getAlgorithm().getParameters());
        assertEquals(1216, spki.getPublicKeyData().getOctets().length);

        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        assertEquals(BCObjectIdentifiers.xwing, pki.getPrivateKeyAlgorithm().getAlgorithm());
        assertNull(pki.getPrivateKeyAlgorithm().getParameters());
        assertEquals(32, pki.getPrivateKey().getOctets().length);
        assertNull(pki.getPublicKeyData());

        KeyFactory kf = KeyFactory.getInstance("X-WING", "BC");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPublic(), pub);
        assertEquals(kp.getPublic().hashCode(), pub.hashCode());
        assertEquals(kp.getPrivate(), priv);
        assertEquals(kp.getPrivate().hashCode(), priv.hashCode());
        assertEquals(kp.getPublic(), ((XWingPrivateKey)priv).getPublicKey());

        X509EncodedKeySpec pubSpec = (X509EncodedKeySpec)kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
        PKCS8EncodedKeySpec privSpec = (PKCS8EncodedKeySpec)kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
        assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), pubSpec.getEncoded()));
        assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), privSpec.getEncoded()));

        KeyFactory oidKf = KeyFactory.getInstance(BCObjectIdentifiers.xwing.getId(), "BC");
        assertEquals(kp.getPublic(), oidKf.generatePublic(pubSpec));
        assertEquals(kp.getPublic(), KeyFactory.getInstance("XWING", "BC").generatePublic(pubSpec));

        // the light-weight factories agree with the provider's encodings
        XWingPublicKeyParameters lwPub = (XWingPublicKeyParameters)PublicKeyFactory.createKey(kp.getPublic().getEncoded());
        XWingPrivateKeyParameters lwPriv = (XWingPrivateKeyParameters)PrivateKeyFactory.createKey(kp.getPrivate().getEncoded());
        assertTrue(Arrays.areEqual(((XWingPublicKey)kp.getPublic()).getPublicData(), lwPub.getEncoded()));
        assertTrue(Arrays.areEqual(pki.getPrivateKey().getOctets(), lwPriv.getSeed()));

        // an ML-KEM key is not an X-Wing key
        KeyPair mlkem = KeyPairGenerator.getInstance("ML-KEM-768", "BC").generateKeyPair();
        try
        {
            kf.generatePublic(new X509EncodedKeySpec(mlkem.getPublic().getEncoded()));
            fail("ML-KEM key accepted");
        }
        catch (java.security.spec.InvalidKeySpecException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("incorrect algorithm OID for key"));
        }
    }

    public void testKeyPairGeneratorInit()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X-WING", "BC");

        kpg.initialize(256, new SecureRandom());
        assertNotNull(kpg.generateKeyPair());

        kpg.initialize(new NamedSpec("X-Wing"), new SecureRandom());
        assertNotNull(kpg.generateKeyPair());

        try
        {
            kpg.initialize(new NamedSpec("X25519"), new SecureRandom());
            fail("foreign spec accepted");
        }
        catch (java.security.InvalidAlgorithmParameterException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("invalid ParameterSpec"));
        }
    }

    /** The shape of java.security.spec.NamedParameterSpec, which the Java 8 test build cannot name. */
    public static class NamedSpec
        implements AlgorithmParameterSpec
    {
        private final String name;

        NamedSpec(String name)
        {
            this.name = name;
        }

        public String getName()
        {
            return name;
        }
    }

    public void testDraftVector()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X-WING", "BC");
        kpg.initialize(256, new FixedSecureRandom(SEED));
        KeyPair kp = kpg.generateKeyPair();

        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        assertTrue(Arrays.areEqual(SEED, pki.getPrivateKey().getOctets()));

        KeyGenerator keyGen = KeyGenerator.getInstance("X-WING", "BC");
        keyGen.init(new KEMGenerateSpec.Builder(kp.getPublic(), "AES", 256).withNoKdf().build(), new FixedSecureRandom(ESEED));

        SecretKeyWithEncapsulation secEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals(1120, secEnc.getEncapsulation().length);
        assertTrue(Arrays.areEqual(SS, secEnc.getEncoded()));

        keyGen.init(new KEMExtractSpec.Builder(kp.getPrivate(), secEnc.getEncapsulation(), "AES", 256).withNoKdf().build());

        assertTrue(Arrays.areEqual(SS, keyGen.generateKey().getEncoded()));
    }

    public void testGenerateAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X-WING", "BC");
        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("X-WING", "BC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));

        // another key pair does not recover the secret
        KeyPair other = kpg.generateKeyPair();
        keyGen.init(new KEMExtractSpec(other.getPrivate(), secEnc1.getEncapsulation(), "AES"));
        assertFalse(Arrays.areEqual(secEnc1.getEncoded(), keyGen.generateKey().getEncoded()));
    }

    public void testKEMCipher()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X-WING", "BC");
        KeyPair kp = kpg.generateKeyPair();

        performKEMScipher(kp, new KEMParameterSpec("AES"));
        performKEMScipher(kp, new KEMParameterSpec("AES-KWP"));
        performKEMScipher(kp, new KTSParameterSpec.Builder("AES", 256).withNoKdf().build());
        performKEMScipher(kp, null);
    }

    private void performKEMScipher(KeyPair kp, KTSParameterSpec ktsParameterSpec)
        throws Exception
    {
        Cipher w1 = Cipher.getInstance("X-WING", "BC");

        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        w1.init(Cipher.WRAP_MODE, kp.getPublic(), ktsParameterSpec);

        byte[] data = w1.wrap(key);

        assertEquals(1120 + (keyBytes.length + 8), data.length);

        Cipher w2 = Cipher.getInstance("X-WING", "BC");

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));

        // tampering with the encapsulation changes the derived key and the unwrap fails
        byte[] tampered = Arrays.clone(data);
        tampered[0] ^= 1;
        try
        {
            w2.unwrap(tampered, "AES", Cipher.SECRET_KEY);
            fail("tampered encapsulation accepted");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }

        try
        {
            w1.init(Cipher.WRAP_MODE, kp.getPrivate(), ktsParameterSpec);
            fail("private key accepted for wrapping");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("Only an X-WING public key can be used for wrapping", e.getMessage());
        }
    }
}
