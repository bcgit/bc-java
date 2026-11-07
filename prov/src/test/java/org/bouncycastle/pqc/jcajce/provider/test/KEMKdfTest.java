package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRULPRimeParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SmaugTParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * The KeyGenerator and Cipher services of NTRU, HQC, NTRU+, NTRU LPRime, SNTRU Prime and SMAUG-T used the raw
 * shared secret whatever KDF the spec named. Both now apply the spec's KDF, as javax.crypto.KEM already did; the
 * expected keys here are derived independently with the lightweight KDF3 (concatenation KDF) implementation.
 */
public class KEMKdfTest
    extends TestCase
{
    private static final String PROV = "BCPQC";

    private static final String[] NAMES = { "NTRU", "HQC", "NTRUPLUS", "NTRULPRIME", "SNTRUPRIME", "SMAUGT" };

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static AlgorithmParameterSpec keySpec(String name)
    {
        if (name.equals("NTRU"))
        {
            return NTRUParameterSpec.ntruhps2048509;
        }
        if (name.equals("HQC"))
        {
            return HQCParameterSpec.hqc128;
        }
        if (name.equals("NTRUPLUS"))
        {
            return NTRUPlusParameterSpec.ntruplus_768;
        }
        if (name.equals("NTRULPRIME"))
        {
            return NTRULPRimeParameterSpec.ntrulpr653;
        }
        if (name.equals("SNTRUPRIME"))
        {
            return SNTRUPrimeParameterSpec.sntrup653;
        }
        return SmaugTParameterSpec.smaugt_mode1;
    }

    private static KeyPair keyPair(String name)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, PROV);
        kpg.initialize(keySpec(name), new SecureRandom());
        return kpg.generateKeyPair();
    }

    private static byte[] kdf3(byte[] secret, int len)
    {
        ConcatenationKDFGenerator kdf = new ConcatenationKDFGenerator(new SHA256Digest());
        kdf.init(new KDFParameters(secret, new byte[0]));
        byte[] out = new byte[len];
        kdf.generateBytes(out, 0, len);
        return out;
    }

    private static byte[] rawSecret(String name, KeyPair kp, byte[] encapsulation)
        throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance(name, PROV);
        keyGen.init(new KEMExtractSpec.Builder(kp.getPrivate(), encapsulation, "Generic", 256).withNoKdf().build());
        return keyGen.generateKey().getEncoded();
    }

    public void testKeyGeneratorAppliesKdf()
        throws Exception
    {
        for (int i = 0; i != NAMES.length; i++)
        {
            String name = NAMES[i];
            KeyPair kp = keyPair(name);
            KeyGenerator keyGen = KeyGenerator.getInstance(name, PROV);

            // the default spec names KDF3 with SHA-256
            keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES", 256), new SecureRandom());
            SecretKeyWithEncapsulation genKey = (SecretKeyWithEncapsulation)keyGen.generateKey();

            keyGen.init(new KEMExtractSpec(kp.getPrivate(), genKey.getEncapsulation(), "AES", 256));
            byte[] extKey = keyGen.generateKey().getEncoded();

            byte[] raw = rawSecret(name, kp, genKey.getEncapsulation());
            assertEquals(name, 32, raw.length);
            assertTrue(name + " generated key not KDF3(secret)", Arrays.areEqual(kdf3(raw, 32), genKey.getEncoded()));
            assertTrue(name + " extracted key not KDF3(secret)", Arrays.areEqual(kdf3(raw, 32), extKey));

            // with a KDF any size is available
            keyGen.init(new KEMExtractSpec(kp.getPrivate(), genKey.getEncapsulation(), "Generic", 512));
            assertTrue(name, Arrays.areEqual(kdf3(raw, 64), keyGen.generateKey().getEncoded()));

            // with no KDF the key is the front of the secret, and no larger than it
            keyGen.init(new KEMExtractSpec.Builder(kp.getPrivate(), genKey.getEncapsulation(), "AES", 128).withNoKdf().build());
            assertTrue(name, Arrays.areEqual(Arrays.copyOfRange(raw, 0, 16), keyGen.generateKey().getEncoded()));

            try
            {
                keyGen.init(new KEMGenerateSpec.Builder(kp.getPublic(), "AES", 384).withNoKdf().build(), new SecureRandom());
                fail(name + " oversize no-KDF key accepted");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                assertTrue(name + ": " + e.getMessage(), e.getMessage().startsWith("no KDF specified and "));
                assertTrue(name + ": " + e.getMessage(), e.getMessage().endsWith(" produces a 256 bit secret, 384 requested"));
            }
        }
    }

    public void testKeyGeneratorRefusesForeignKey()
        throws Exception
    {
        KeyPair other = keyPair("SMAUGT");
        for (int i = 0; i != NAMES.length - 1; i++)
        {
            KeyGenerator keyGen = KeyGenerator.getInstance(NAMES[i], PROV);
            try
            {
                keyGen.init(new KEMGenerateSpec(other.getPublic(), "AES", 256), new SecureRandom());
                fail(NAMES[i] + " accepted a SMAUG-T key");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                // expected
            }
        }
    }

    public void testCipherAppliesKdf()
        throws Exception
    {
        byte[] keyBytes = Arrays.copyOfRange(kdf3(new byte[]{ 1, 2, 3 }, 32), 0, 16);
        Key toWrap = new SecretKeySpec(keyBytes, "AES");

        for (int i = 0; i != NAMES.length; i++)
        {
            String name = NAMES[i];
            KeyPair kp = keyPair(name);

            // encapsulation length, from the KeyGenerator
            KeyGenerator keyGen = KeyGenerator.getInstance(name, PROV);
            keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES", 256), new SecureRandom());
            int encLen = ((SecretKeyWithEncapsulation)keyGen.generateKey()).getEncapsulation().length;

            // a KTSParameterSpec names KDF3 with SHA-256 by default
            KTSParameterSpec kdfSpec = new KTSParameterSpec.Builder("AES", 256).build();
            byte[] wrapped = wrap(name, kp, kdfSpec, toWrap);
            byte[] raw = rawSecret(name, kp, Arrays.copyOfRange(wrapped, 0, encLen));
            assertTrue(name + " KEK not KDF3(secret)",
                Arrays.areEqual(keyBytes, aesUnwrap(kdf3(raw, 32), Arrays.copyOfRange(wrapped, encLen, wrapped.length))));
            assertTrue(name, Arrays.areEqual(keyBytes, unwrap(name, kp, kdfSpec, wrapped)));

            // the legacy KEMParameterSpec names no KDF, and still wraps under the raw secret, as before
            KEMParameterSpec noKdfSpec = new KEMParameterSpec("AES");
            wrapped = wrap(name, kp, noKdfSpec, toWrap);
            raw = rawSecret(name, kp, Arrays.copyOfRange(wrapped, 0, encLen));
            assertTrue(name + " no-KDF KEK not the raw secret",
                Arrays.areEqual(keyBytes, aesUnwrap(raw, Arrays.copyOfRange(wrapped, encLen, wrapped.length))));
            assertTrue(name, Arrays.areEqual(keyBytes, unwrap(name, kp, noKdfSpec, wrapped)));

            // nor are the two interchangeable
            try
            {
                unwrap(name, kp, kdfSpec, wrapped);
                fail(name + " no-KDF wrap unwrapped under the KDF");
            }
            catch (Exception e)
            {
                // expected
            }
        }
    }

    private static byte[] wrap(String name, KeyPair kp, AlgorithmParameterSpec spec, Key key)
        throws Exception
    {
        Cipher c = Cipher.getInstance(name, PROV);
        c.init(Cipher.WRAP_MODE, kp.getPublic(), spec, new SecureRandom());
        return c.wrap(key);
    }

    private static byte[] unwrap(String name, KeyPair kp, AlgorithmParameterSpec spec, byte[] wrapped)
        throws Exception
    {
        Cipher c = Cipher.getInstance(name, PROV);
        c.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        return c.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded();
    }

    private static byte[] aesUnwrap(byte[] kek, byte[] wrapped)
        throws Exception
    {
        AESWrapEngine engine = new AESWrapEngine();
        engine.init(false, new KeyParameter(kek));
        return engine.unwrap(wrapped, 0, wrapped.length);
    }
}
