package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The legacy PBES1 and PKCS#12 PBE families bound the iteration count they derive with, as PBKDF2 does, since the count
 * usually arrives in an unauthenticated parameters field and the derivation runs before anything can be verified.
 */
public class PBEIterationCountTest
    extends SimpleTest
{
    private static final int TEST_MAX = 1000;

    // well above TEST_MAX, but cheap enough that a build without the bound finishes the derivation quickly
    private static final int OVER_MAX = 1000000;

    private static final byte[] SALT = new byte[8];

    public String getName()
    {
        return "PBEIterationCount";
    }

    public void performTest()
        throws Exception
    {
        String oldMax = System.getProperty(Properties.PBE_MAX_ITERATION_COUNT);
        System.setProperty(Properties.PBE_MAX_ITERATION_COUNT, Integer.toString(TEST_MAX));
        try
        {
            testAlgorithmParameters();
            testCipher();
            testMac();
            testSecretKeyFactory();
            testEncryptedPrivateKeyInfo();
            testWithinBound();
        }
        finally
        {
            if (oldMax == null)
            {
                System.getProperties().remove(Properties.PBE_MAX_ITERATION_COUNT);
            }
            else
            {
                System.setProperty(Properties.PBE_MAX_ITERATION_COUNT, oldMax);
            }
        }

        testDefaultBound();
    }

    private void testAlgorithmParameters()
        throws Exception
    {
        String[] names = { "PKCS12PBE", PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC.getId(),
            PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC.getId(), "PBKDF1" };

        for (int i = 0; i != names.length; i++)
        {
            checkParamsRejected(names[i], BigInteger.valueOf(OVER_MAX), "iteration count (" + OVER_MAX + ") greater than " + TEST_MAX);
            checkParamsRejected(names[i], BigInteger.valueOf(Integer.MAX_VALUE), "iteration count (2147483647) greater than " + TEST_MAX);
            // 2^32 used to be narrowed to 0 by intValue()
            checkParamsRejected(names[i], BigInteger.ONE.shiftLeft(32), "invalid iteration count (4294967296)");
            checkParamsRejected(names[i], BigInteger.valueOf(-1), "invalid iteration count (-1)");

            AlgorithmParameters params = AlgorithmParameters.getInstance(names[i], "BC");
            params.init(pbeParams(BigInteger.valueOf(TEST_MAX)));
            isEquals(TEST_MAX, ((PBEParameterSpec)params.getParameterSpec(PBEParameterSpec.class)).getIterationCount());
        }
    }

    private void checkParamsRejected(String name, BigInteger count, String message)
        throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance(name, "BC");
        try
        {
            params.init(pbeParams(count));
            fail(name + ": count " + count + " accepted");
        }
        catch (java.io.IOException e)
        {
            isEquals(name, message, e.getMessage());
        }
    }

    private void testCipher()
        throws Exception
    {
        SecretKey pbeKey = pbeKey("PBEWithSHAAnd3-KeyTripleDES-CBC");

        // BCPBEKey without derived parameters, block cipher
        checkCipherRejected("PBEWithSHAAnd3-KeyTripleDES-CBC", pbeKey, OVER_MAX);
        checkCipherRejected("PBEWithSHAAnd3-KeyTripleDES-CBC", pbeKey, -1);
        // a key that is not a BCPBEKey takes the raw-key derivation
        checkCipherRejected("PBEWithSHAAnd3-KeyTripleDES-CBC", new SecretKeySpec(Strings.toByteArray("password"), "PBE"), OVER_MAX);
        // PBES1 (PKCS#5 scheme 1)
        checkCipherRejected("PBEWithMD5AndDES", pbeKey("PBEWithMD5AndDES"), OVER_MAX);
        // stream cipher
        checkCipherRejected("PBEWithSHAAnd128BitRC4", pbeKey("PBEWithSHAAnd128BitRC4"), OVER_MAX);
    }

    private void checkCipherRejected(String name, SecretKey key, int count)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance(name, "BC");
        try
        {
            cipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(SALT, count));
            fail(name + ": count " + count + " accepted");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue(name + ": " + e.getMessage(), isIterationCountMessage(e.getMessage()));
        }
    }

    private void testMac()
        throws Exception
    {
        String[] names = { "PBEWithHMacSHA1", "PBEWithHMacSHA256" };

        for (int i = 0; i != names.length; i++)
        {
            SecretKey[] keys = { pbeKey("PBEWithHMacSHA1"), new PKCS12Key("password".toCharArray()) };
            for (int j = 0; j != keys.length; j++)
            {
                Mac mac = Mac.getInstance(names[i], "BC");
                try
                {
                    mac.init(keys[j], new PBEParameterSpec(SALT, OVER_MAX));
                    fail(names[i] + ": count accepted");
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    isTrue(names[i] + ": " + e.getMessage(), isIterationCountMessage(e.getMessage()));
                }
            }
        }
    }

    private void testSecretKeyFactory()
        throws Exception
    {
        // PBESecretKeyFactory (PKCS#12 cipher and MAC), and the DES key factory's own derivation (PBES1)
        String[] names = { "PBEWithSHAAnd3-KeyTripleDES-CBC", "PBEWithHMacSHA1", "PBEWithMD5AndDES" };

        for (int i = 0; i != names.length; i++)
        {
            SecretKeyFactory fact = SecretKeyFactory.getInstance(names[i], "BC");
            try
            {
                fact.generateSecret(new PBEKeySpec("password".toCharArray(), SALT, OVER_MAX, 64));
                fail(names[i] + ": count accepted");
            }
            catch (InvalidKeySpecException e)
            {
                isTrue(names[i] + ": " + e.getMessage(), isIterationCountMessage(e.getMessage()));
            }
        }
    }

    /**
     * The report's end-to-end case: EncryptedPrivateKeyInfo.getKeySpec() on a PKCS#12 PBE blob, where the JDK's own
     * provider decodes the parameters and BC's Cipher only ever sees the resulting PBEParameterSpec.
     */
    private void testEncryptedPrivateKeyInfo()
        throws Exception
    {
        ASN1ObjectIdentifier[] oids = { PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
            PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC };

        for (int i = 0; i != oids.length; i++)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new AlgorithmIdentifier(oids[i], ASN1Primitive.fromByteArray(pbeParams(BigInteger.valueOf(OVER_MAX)))));
            v.add(new DEROctetString(new byte[24]));
            byte[] encoding = new DERSequence(v).getEncoded();

            try
            {
                EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(encoding);
                epki.getKeySpec(pbeKey("PBEWithSHAAnd3-KeyTripleDES-CBC"), "BC");
                fail(oids[i] + ": key spec returned");
            }
            catch (Exception e)
            {
                isTrue(oids[i] + ": " + e, hasIterationCountCause(e));
            }
        }
    }

    private void testWithinBound()
        throws Exception
    {
        SecretKey key = pbeKey("PBEWithSHAAnd3-KeyTripleDES-CBC");
        byte[] data = Strings.toByteArray("hello world!");

        int[] counts = { 0, 1, TEST_MAX };
        for (int i = 0; i != counts.length; i++)
        {
            PBEParameterSpec spec = new PBEParameterSpec(SALT, counts[i]);

            Cipher cipher = Cipher.getInstance("PBEWithSHAAnd3-KeyTripleDES-CBC", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] ct = cipher.doFinal(data);

            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            isTrue("count " + counts[i], Arrays.areEqual(data, cipher.doFinal(ct)));

            Mac mac = Mac.getInstance("PBEWithHMacSHA1", "BC");
            mac.init(pbeKey("PBEWithHMacSHA1"), spec);
            mac.doFinal(data);

            if (counts[i] > 0)      // PBEKeySpec itself refuses a zero count
            {
                SecretKeyFactory.getInstance("PBEWithSHAAnd3-KeyTripleDES-CBC", "BC")
                    .generateSecret(new PBEKeySpec("password".toCharArray(), SALT, counts[i], 192));
            }
        }
    }

    private void testDefaultBound()
        throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance("PKCS12PBE", "BC");
        params.init(pbeParams(BigInteger.valueOf(10000000)));

        checkDefaultRejected("PKCS12PBE", 10000001);
        checkDefaultRejected("PBKDF1", Integer.MAX_VALUE);

        Cipher cipher = Cipher.getInstance("PBEWithSHAAnd3-KeyTripleDES-CBC", "BC");
        try
        {
            cipher.init(Cipher.DECRYPT_MODE, pbeKey("PBEWithSHAAnd3-KeyTripleDES-CBC"), new PBEParameterSpec(SALT, Integer.MAX_VALUE));
            fail("default bound not applied");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isEquals("iteration count (2147483647) greater than 10000000", e.getMessage());
        }
    }

    private void checkDefaultRejected(String name, int count)
        throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance(name, "BC");
        try
        {
            params.init(pbeParams(BigInteger.valueOf(count)));
            fail(name + ": default bound not applied");
        }
        catch (java.io.IOException e)
        {
            isEquals("iteration count (" + count + ") greater than 10000000", e.getMessage());
        }
    }

    private static SecretKey pbeKey(String algorithm)
        throws Exception
    {
        return SecretKeyFactory.getInstance(algorithm, "BC").generateSecret(new PBEKeySpec("password".toCharArray()));
    }

    // PKCS12PBEParams and PBEParameter share the SEQUENCE { OCTET STRING, INTEGER } shape
    private static byte[] pbeParams(BigInteger count)
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(SALT));
        v.add(new ASN1Integer(count));
        return new DERSequence(v).getEncoded();
    }

    private static boolean isIterationCountMessage(String message)
    {
        return message != null && message.indexOf("iteration count") >= 0;
    }

    private static boolean hasIterationCountCause(Throwable t)
    {
        for (; t != null; t = t.getCause())
        {
            if (isIterationCountMessage(t.getMessage()))
            {
                return true;
            }
        }
        return false;
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PBEIterationCountTest());
    }
}
