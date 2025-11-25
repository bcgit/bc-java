package org.bouncycastle.jcajce.provider.kdf.test;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.spec.PBKDF2ParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.spec.HKDFParameterSpec;

import javax.crypto.KDF;
import javax.crypto.KDFParameters;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;

import static org.bouncycastle.util.Arrays.areEqual;

public class HKDFTest
        extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKDF()
            throws Exception
    {

        setUp();
        KDF kdfHkdf = KDF.getInstance("HKDF-SHA256", "BC");

        byte[] ikm = Hex.decode("c702e7d0a9e064b09ba55245fb733cf3");
        byte[] salt = Strings.toByteArray("The Cryptographic Message Syntax");
        byte[] info = Hex.decode("301b0609608648016503040106300e040c5c79058ba2f43447639d29e2");
        byte[] okm = Hex.decode("2124ffb29fac4e0fbbc7d5d87492bff3");
        byte[] genOkm;
        HKDFParameterSpec.ExtractThenExpand hkdfParams1 = HKDFParameterSpec.ofExtract().addIKM(ikm)
                                                                          .addSalt(salt).thenExpand(info, okm.length);

        genOkm = kdfHkdf.deriveData(hkdfParams1);

        if (!areEqual(genOkm, okm))
        {
            fail("HKDF failed generator test");
        }

        // Extract Only
        ikm = Hex.decode("c702e7d0a9e064b09ba55245fb733cf3");
        salt = Strings.toByteArray("The Cryptographic Message Syntax");
        okm = Hex.decode("4d757351dc7a354f041aacd288c8957e341ac8903ba8b4debde8e856f1b58e31");

        HKDFParameterSpec.Extract hkdfParams2 = HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(salt).extractOnly();

        genOkm = kdfHkdf.deriveData(hkdfParams2);

        if (!areEqual(genOkm, okm))
        {
            fail("HKDF failed generator test");
        }

        //TODO: make test for derived keys
//        kdfHkdf.deriveKey("AES", hkdfParams);

        //TODO: do we want users to initialize the digest?
        //KDF kdf = KDF.getInstance("HKDF", "BC");
        //kdf.init(new KDFParameter(new SHA1Digest()));
        //kdf.deriveData(hkdfParams);
    }
    private boolean doComparison(String algorithm, byte[] ikm, byte[] salt, byte[] info)
            throws Exception
    {
        KDF kdf = KDF.getInstance(algorithm, "BC");
        HKDFParameterSpec.ExtractThenExpand spec = HKDFParameterSpec.ofExtract().addIKM(ikm)
                                                                          .addSalt(salt).thenExpand(info, ikm.length);

        org.bouncycastle.jcajce.spec.HKDFParameterSpec pre25spec = new org.bouncycastle.jcajce.spec.HKDFParameterSpec(ikm, salt, info, ikm.length);
        byte[] kdfSecret = kdf.deriveData(spec);

        SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, "BC");
        SecretKey factSecret = fact.generateSecret(pre25spec);

        return Arrays.areEqual(kdfSecret, factSecret.getEncoded());
    }

    public void testSecretKeyFactoryComparison()
            throws Exception
    {
        setUp();
        String[] algorithms = new String[] {
                "HKDF-SHA256",
                "HKDF-SHA384",
                "HKDF-SHA512",
        };
        byte[] ikm = new byte[16];
        byte[] salt = new byte[16];
        byte[] info = new byte[16];
        SecureRandom random = new SecureRandom();
        for (String algorithm: algorithms)
        {
            random.nextBytes(ikm);
            random.nextBytes(salt);
            random.nextBytes(info);
            if(!doComparison(algorithm, ikm, salt, info))
            {
                fail("failed to generate same secret using kdf and secret key factory for: " + algorithm);
            }
        }
    }

    public void testExceptionHandling()
    {
        setUp();
        try
        {
            KDF kdf = KDF.getInstance("NonExistentAlgorithm", "BC");
            fail("Exception was not thrown for nonexistent algorithm");
        }
        catch (Exception e)
        {
            assertTrue(e instanceof NoSuchAlgorithmException);
        }
        try
        {
            KDF kdf = KDF.getInstance("HKDF-SHA256", "NonExistentProvider");
            fail("Exception was not thrown for nonexistent provider");
        }
        catch (Exception e)
        {
            assertTrue(e instanceof NoSuchProviderException);
        }
        try
        {
            KDF kdf = KDF.getInstance(null, "BC");
            fail("Exception was not thrown for null algorithm");
        }
        catch (Exception e)
        {
            assertTrue(e instanceof NullPointerException);
        }
        try
        {
            KDFParameters kdfParameters = new InvalidKDFParameters();
            KDF kdf = KDF.getInstance("HKDF-SHA256", kdfParameters, "BC");
            fail("Exception was not thrown for valid algorithm, but invalid parameters");
        }
        catch (Exception e)
        {
            assertTrue(e instanceof InvalidAlgorithmParameterException);
        }
        try
        {
            KDF kdf = KDF.getInstance("HKDF-SHA256", "BC");
            PBKDF2ParameterSpec pbepbkdf2ParameterSpec = new PBKDF2ParameterSpec(new char[16], new byte[16], 16);
            kdf.deriveData(pbepbkdf2ParameterSpec);
            fail("Exception was not thrown for invalid derivation spec");
        }
        catch (Exception e)
        {
            assertTrue(e instanceof InvalidAlgorithmParameterException);
        }
        //TODO: check if the derived keying material is not extractable
//        try
//        {
//            KDF kdf = KDF.getInstance("HKDF-SHA256", "BC");
//            HKDFParameterSpec hkdfParameterSpec = HKDFParameterSpec.skipExtractParameters(new byte[16], new byte[16]);
//            kdf.deriveData(hkdfParameterSpec);
//            fail("Exception was not thrown for invalid derivation spec");
//        }
//        catch (Exception e)
//        {
//            assertTrue(e instanceof InvalidAlgorithmParameterException);
//        }
    }

    private static class InvalidKDFParameters
            implements KDFParameters
    {

        public InvalidKDFParameters()
        {
            super();
        }


        @Override
        public int hashCode()
        {
            return super.hashCode();
        }


        @Override
        public boolean equals(Object obj)
        {
            return super.equals(obj);
        }


        @Override
        protected Object clone() throws CloneNotSupportedException
        {
            return super.clone();
        }


        @Override
        public String toString()
        {
            return super.toString();
        }

    }
}
