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
        String[] algorithms = new String[]{
                "HKDF-SHA256",
                "HKDF-SHA384",
                "HKDF-SHA512",
        };
        byte[] ikm = new byte[16];
        byte[] salt = new byte[16];
        byte[] info = new byte[16];
        SecureRandom random = new SecureRandom();
        for (String algorithm : algorithms)
        {
            random.nextBytes(ikm);
            random.nextBytes(salt);
            random.nextBytes(info);
            if (!doComparison(algorithm, ikm, salt, info))
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

    public void testExtractWithConcatenatedIKMAndSalts()
            throws Exception
    {
        setUp();
        KDF kdfHkdf = KDF.getInstance("HKDF-SHA256", "BC");

        byte[][] ikms = new byte[][]
                {
                        Hex.decode("000102030405060708090a0b0c0d0e0f"),
                        Hex.decode("101112131415161718191a1b1c1d1e1f"),
                        Hex.decode("202122232425262728292a2b2c2d2e2f"),
                        Hex.decode("303132333435363738393a3b3c3d3e3f"),
                        Hex.decode("404142434445464748494a4b4c4d4e4f"),
                };

        byte[][] salts = new byte[][]
                {
                        Hex.decode("606162636465666768696a6b6c6d6e6f"),
                        Hex.decode("707172737475767778797a7b7c7d7e7f"),
                        Hex.decode("808182838485868788898a8b8c8d8e8f"),
                        Hex.decode("909192939495969798999a9b9c9d9e9f"),
                        Hex.decode("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                };
        byte[] info = Hex.decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] okm = Hex.decode(
                "b11e398dc80327a1c8e7f78c596a4934" +
                        "4f012eda2d4efad8a050cc4c19afa97c" +
                        "59045a99cac7827271cb41c65e590e09" +
                        "da3275600c2f09b8367793a9aca3db71" +
                        "cc30c58179ec3e87c14c01d5c1f3434f" +
                        "1d87");

        HKDFParameterSpec.ExtractThenExpand hkdfParams1 = HKDFParameterSpec.ofExtract()
                .addIKM(ikms[0]).addIKM(ikms[1]).addIKM(ikms[2]).addIKM(ikms[3]).addIKM(ikms[4])
                .addSalt(salts[0]).addSalt(salts[1]).addSalt(salts[2]).addSalt(salts[3]).addSalt(salts[4])
                .thenExpand(info, okm.length);

        byte[] genOkm = kdfHkdf.deriveData(hkdfParams1);

        if (!areEqual(genOkm, okm))
        {
            fail("HKDF failed for multiple ikms/salts");
        }

        HKDFParameterSpec.Extract hkdfParams2 = HKDFParameterSpec.ofExtract()
                .addIKM(ikms[0]).addIKM(ikms[1]).addIKM(ikms[2]).addIKM(ikms[3]).addIKM(ikms[4])
                .addSalt(salts[0]).addSalt(salts[1]).addSalt(salts[2]).addSalt(salts[3]).addSalt(salts[4])
                .extractOnly();

        okm = Hex.decode("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        genOkm = kdfHkdf.deriveData(hkdfParams2);

        if (!areEqual(genOkm, okm))
        {
            fail("HKDF failed for multiple ikms/salts");
        }
    }

    /**
     * Helper method to concatenate two byte arrays.
     */
    private byte[] concatenate(byte[] first, byte[] second)
    {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
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
