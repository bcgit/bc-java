package org.bouncycastle.jcajce.provider.kdf.test;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.spec.ScryptParameterSpec;
import org.bouncycastle.jcajce.spec.HKDFParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

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

public class ScryptTest
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
        KDF kdf = KDF.getInstance("Scrypt", "BC");

        byte[] expected = Hex.decode("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
        ScryptParameterSpec spec = new ScryptParameterSpec(
                "".toCharArray(),
                Strings.toByteArray(""),
                16,
                1,
                1,
                64*8
        );
        if(!areEqual(kdf.deriveData(spec), expected))
        {
            fail("Scrypt failed test");
        }

        expected = Hex.decode("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
        spec = new ScryptParameterSpec(
                "password".toCharArray(),
                Strings.toByteArray("NaCl"),
                1024,
                8,
                16,
                64*8
        );
        if(!areEqual(kdf.deriveData(spec), expected))
        {
            fail("Scrypt failed test");
        }

        expected = Hex.decode("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");
        spec = new ScryptParameterSpec(
                "pleaseletmein".toCharArray(),
                Strings.toByteArray("SodiumChloride"),
                16384,
                8,
                1,
                64*8
        );
        if(!areEqual(kdf.deriveData(spec), expected))
        {
            fail("Scrypt failed test");
        }

        expected = Hex.decode("2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4");
        spec = new ScryptParameterSpec(
                "pleaseletmein".toCharArray(),
                Strings.toByteArray("SodiumChloride"),
                1048576,
                8,
                1,
                64*8
        );
        if(!areEqual(kdf.deriveData(spec), expected))
        {
            fail("Scrypt failed test");
        }


    }
    
        public void testSecretKeyFactoryComparison()
            throws Exception
    {

        setUp();
        KDF kdf = KDF.getInstance("Scrypt", "BC");
        byte[] password = new byte[16];
        byte[] salt = new byte[8];

        SecureRandom random = new SecureRandom();
        random.nextBytes(password);
        random.nextBytes(salt);

        ScryptParameterSpec spec = new ScryptParameterSpec(
                Hex.toHexString(password).toCharArray(),
                salt,
                1024,
                8,
                16,
                64
        );
        byte[] kdfSecret = kdf.deriveData(spec);

        SecretKeyFactory fact = SecretKeyFactory.getInstance("SCRYPT", "BC");

        spec = new ScryptParameterSpec(
                Hex.toHexString(password).toCharArray(),
                salt,
                1024,
                8,
                16,
                64
        );
        SecretKey factSecret = fact.generateSecret(spec);
        byte[] byteSecret = factSecret.getEncoded();

        if(!areEqual(kdfSecret, byteSecret))
        {
            fail("failed to generate same secret using kdf and secret key factory for: " + "Scrypt");
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
            KDF kdf = KDF.getInstance("SCRYPT", "NonExistentProvider");
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
            KDF kdf = KDF.getInstance("SCRYPT", kdfParameters, "BC");
            fail("Exception was not thrown for valid algorithm, but invalid parameters");
        }
        catch (Exception e)
        {
            assertTrue(e instanceof InvalidAlgorithmParameterException);
        }
        try
        {
            KDF kdf = KDF.getInstance("SCRYPT", "BC");
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
