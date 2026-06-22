package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.pqc.jcajce.interfaces.NTRUPlusKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class NTRUPlusTest
    extends TestCase
{

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testBasicKEMAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_768, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRUPLUS", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "NTRUPLUS", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(NTRUPlusParameterSpec.ntruplus_864, new SecureRandom());
        KeyPair hqcKp = kpg.generateKeyPair();
        performKEMScipher(hqcKp, "NTRUPLUS", new KEMParameterSpec("AES"));
        performKEMScipher(hqcKp, "NTRUPLUS", new KEMParameterSpec("AES-KWP"));
    }

    public void testBasicKEMCamellia()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_768, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRUPLUS", new KEMParameterSpec("Camellia"));
        performKEMScipher(kpg.generateKeyPair(), "NTRUPLUS", new KEMParameterSpec("Camellia-KWP"));
    }

    public void testBasicKEMSEED()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_768, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRUPLUS", new KEMParameterSpec("SEED"));
    }

    public void testBasicKEMARIA()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_768, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRUPLUS", new KEMParameterSpec("ARIA"));
        performKEMScipher(kpg.generateKeyPair(), "NTRUPLUS", new KEMParameterSpec("ARIA-KWP"));
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KEMParameterSpec ktsParameterSpec)
        throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BCPQC");

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

        Cipher w2 = Cipher.getInstance(algorithm, "BCPQC");

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
    }

    public void testGenerateAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_768, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("NTRUPLUS", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testGenerateAES256()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_864, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("NTRUPLUS", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testParameterSpecRoundTrip()
        throws Exception
    {
        NTRUPlusParameterSpec[] specs =
            {
                NTRUPlusParameterSpec.ntruplus_768,
                NTRUPlusParameterSpec.ntruplus_864,
                NTRUPlusParameterSpec.ntruplus_1152
            };

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            // fromName(spec.getName()) must round-trip to the same constant
            assertSame(specs[i], NTRUPlusParameterSpec.fromName(specs[i].getName()));

            kpg.initialize(specs[i], new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            // getParameterSpec() resolves the spec from a key (was null before the fix)
            assertSame(specs[i], ((NTRUPlusKey)kp.getPublic()).getParameterSpec());
            assertSame(specs[i], ((NTRUPlusKey)kp.getPrivate()).getParameterSpec());
        }
    }

    public void testParameterLockedKeyGenerator()
        throws Exception
    {
        // Obtaining the KeyGenerator through a per-parameter-set alias makes the
        // SPI parameter-locked, so engineInit runs the fromName(...).getName()
        // path that previously NPE'd (and the alias itself previously failed to
        // resolve at all because its registered class name was misspelt).
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_768, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("NTRU+KEM-768", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation enc = (SecretKeyWithEncapsulation)keyGen.generateKey();

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), enc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation dec = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertTrue(Arrays.areEqual(enc.getEncoded(), dec.getEncoded()));

        // a key from a different parameter set must be rejected, naming the
        // canonical (no-hyphen) algorithm the generator is locked to
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_864, new SecureRandom());
        KeyPair other = kpg.generateKeyPair();
        try
        {
            keyGen.init(new KEMGenerateSpec(other.getPublic(), "AES"), new SecureRandom());
            fail("expected lock mismatch to be rejected");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key generator locked to NTRU+KEM768", e.getMessage());
        }
    }

    public void testParameterLockedCipher()
        throws Exception
    {
        // The per-parameter-set Cipher alias must resolve (its registered class
        // name was misspelt) and must accept a key of its own parameter set (the
        // 768 alias was wired to the 864 parameters, so it rejected real 768 keys).
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_768, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRU+KEM-768", new KEMParameterSpec("AES"));
    }

    public void testPerParameterKeyPairGeneratorAliases()
        throws Exception
    {
        // Each per-parameter-set KeyPairGenerator alias must produce keys of THAT
        // parameter set (the 1152 alias was wired to the 864 parameters).
        String[] aliases = { "NTRU+KEM-768", "NTRU+KEM-864", "NTRU+KEM-1152" };
        NTRUPlusParameterSpec[] specs =
            {
                NTRUPlusParameterSpec.ntruplus_768,
                NTRUPlusParameterSpec.ntruplus_864,
                NTRUPlusParameterSpec.ntruplus_1152
            };

        for (int i = 0; i != aliases.length; i++)
        {
            // uninitialised: the alias' locked parameter set drives keygen
            KeyPair kp = KeyPairGenerator.getInstance(aliases[i], "BCPQC").generateKeyPair();
            assertEquals(specs[i].getName(), kp.getPublic().getAlgorithm());
            assertSame(specs[i], ((NTRUPlusKey)kp.getPublic()).getParameterSpec());

            // explicitly initialising with the matching spec must not be rejected
            KeyPairGenerator locked = KeyPairGenerator.getInstance(aliases[i], "BCPQC");
            locked.initialize(specs[i], new SecureRandom());
            locked.generateKeyPair();
        }
    }
}
