package org.bouncycastle.jcajce.provider.kdf.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.spec.HKDFParameterSpec;
import org.bouncycastle.jcajce.spec.PBKDF2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KDF;
import javax.crypto.KDFParameters;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import static org.bouncycastle.util.Arrays.areEqual;

public class PBEPBKDF2Test
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
        KDF kdf = KDF.getInstance("PBKDF2WITH8BIT", "BC");
        //
        // RFC 3211 tests
        //
        char[] password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        byte[]  salt = Hex.decode("1234567878563412");

        PBKDF2ParameterSpec spec = new PBKDF2ParameterSpec(password, salt, 5, 64);

//        if (!areEqual((kdf.deriveKey("AES", spec).getEncoded()), Hex.decode("d1daa78615f287e6")))
        if (!areEqual(kdf.deriveData(spec), Hex.decode("d1daa78615f287e6")))
        {
            fail("64 test failed");
        }

        password = "All n-entities must communicate with other n-entities via n-1 entiteeheehees".toCharArray();
        spec = new PBKDF2ParameterSpec(password, salt, 500, 192);


        if (!areEqual((kdf.deriveData(spec)), Hex.decode("6a8970bf68c92caea84a8df28510858607126380cc47ab2d")))
        {
            fail("192 test failed");
        }

        spec = new PBKDF2ParameterSpec(password, salt, 60000, 192);
        if (!areEqual((kdf.deriveData(spec)), Hex.decode("29aaef810c12ecd2236bbcfb55407f9852b5573dc1c095bb")))
        {
            fail("192 (60000) test failed");
        }
    }

    private boolean doComparison(String algorithm, char[] password, byte[] salt, int iterCount, int keyLen)
            throws Exception
    {
        KDF kdf = KDF.getInstance(algorithm, "BC");
        PBKDF2ParameterSpec spec = new PBKDF2ParameterSpec(password, salt, iterCount, keyLen);
        byte[] kdfSecret = kdf.deriveData(spec);

        SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, "BC");
        SecretKey factSecret = fact.generateSecret(spec);

        return Arrays.areEqual(kdfSecret, factSecret.getEncoded());
    }

    public void test8BitOnUTF()
        throws Exception
    {
        char[] glyph1_utf16 = { 0xd801, 0xdc00 };
        byte[] salt = Strings.toByteArray("salt");
        int iter = 100;
        int keySize = 128;

        PBEKeySpec pbeks = new PBEKeySpec(glyph1_utf16, salt, iter, keySize);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA1AND8BIT", "BC");

        SecretKey sKey = skf.generateSecret(pbeks);

        if (!Arrays.areEqual(Hex.decode("470310cc8533df28b6f74fff81707b5a"), sKey.getEncoded()))
        {
            fail("8bit key mismatch");
        }

        KDF kdf = KDF.getInstance("PBKDF2WITHHMACSHA1AND8BIT", "BC");

        PBKDF2ParameterSpec spec = new PBKDF2ParameterSpec(glyph1_utf16, salt, iter, keySize);

        byte[] kdfSecret = kdf.deriveData(spec);

        if (!Arrays.areEqual(Hex.decode("470310cc8533df28b6f74fff81707b5a"), kdfSecret))
        {
            fail("KDF 8bit key mismatch");
        }
    }
    
    public void testSecretKeyFactoryComparison()
            throws Exception
    {
        setUp();
        String[] algorithms = new String[] {
                "PBKDF2",
                "PBKDF2WITHHMACSHA1",
                "PBKDF2WITHHMACSHA1ANDUTF8",
                PKCSObjectIdentifiers.id_PBKDF2.toString(),
                "PBKDF2WITHASCII",
                "PBKDF2WITH8BIT",
                "PBKDF2WITHHMACSHA1AND8BIT",
                "PBKDF2WITHHMACSHA224",
                "PBKDF2WITHHMACSHA256",
                "PBKDF2WITHHMACSHA384",
                "PBKDF2WITHHMACSHA512",
                "PBKDF2WITHHMACSHA512-224",
                "PBKDF2WITHHMACSHA512-256",
                "PBKDF2WITHHMACSHA3-224",
                "PBKDF2WITHHMACSHA3-256",
                "PBKDF2WITHHMACSHA3-384",
                "PBKDF2WITHHMACSHA3-512",
                "PBKDF2WITHHMACGOST3411",
                "PBKDF2WITHHMACSM3",
        };
//        char[] password = new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        byte[] password = new byte[16];
        byte[] salt = new byte[8];
        SecureRandom random = new SecureRandom();
        for (String algorithm: algorithms)
        {
            random.nextBytes(password);
            random.nextBytes(salt);
            if(!doComparison(algorithm, Hex.toHexString(password).toCharArray(), salt, 16, 64))
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
            KDF kdf = KDF.getInstance("PBKDF2", "NonExistentProvider");
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
            KDF kdf = KDF.getInstance("PBKDF2", kdfParameters, "BC");
            fail("Exception was not thrown for valid algorithm, but invalid parameters");
        }
        catch (Exception e)
        {
            assertTrue(e instanceof InvalidAlgorithmParameterException);
        }
        try
        {
            KDF kdf = KDF.getInstance("PBKDF2", "BC");
            HKDFParameterSpec hkdfParameterSpec = new HKDFParameterSpec(new byte[16], new byte[16], new byte[16], 16);
            kdf.deriveData(hkdfParameterSpec);
            fail("Exception was not thrown for invalid derivation spec");
        }
        catch (Exception e)
        {
            assertTrue(e instanceof InvalidAlgorithmParameterException);
        }
    }

    private class InvalidKDFParameters
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
