package org.bouncycastle.jce.provider.test;

import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jcajce.spec.Argon2KeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Argon2KeyFactoryTest
    extends SimpleTest
{
    public String getName()
    {
        return "Argon2KeyFactory";
    }

    public void performTest()
        throws Exception
    {
        knownAnswerTest();
        matchesLightweightTest();
        invalidSpecTest();
    }

    // RFC 9106 reference vector: Argon2i, v1.3, t=2, m=2^16 KiB, p=1, "password"/"somesalt", 32 bytes.
    private void knownAnswerTest()
        throws Exception
    {
        Argon2KeySpec spec = new Argon2KeySpec(
            Argon2KeySpec.ARGON2_i, Argon2KeySpec.ARGON2_VERSION_13,
            "password".toCharArray(), Strings.toByteArray("somesalt"),
            2, 1 << 16, 1, 256);

        SecretKeyFactory fact = SecretKeyFactory.getInstance("ARGON2", "BC");
        SecretKey key = fact.generateSecret(spec);

        isEquals("ARGON2", key.getAlgorithm());

        if (!Arrays.areEqual(Hex.decode("c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0"), key.getEncoded()))
        {
            fail("ARGON2 known answer mismatch");
        }
    }

    // The JCE SecretKeyFactory must agree with the lightweight generator for the default
    // (Argon2id, v1.3) construction, proving the spec parameters are threaded through correctly.
    private void matchesLightweightTest()
        throws Exception
    {
        byte[] salt = Strings.toByteArray("0123456789abcdef");
        char[] password = "hello world".toCharArray();

        Argon2KeySpec spec = new Argon2KeySpec(password, salt, 3, 1 << 14, 2, 256);

        SecretKey key = SecretKeyFactory.getInstance("ARGON2", "BC").generateSecret(spec);

        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withIterations(3)
            .withMemoryAsKB(1 << 14)
            .withParallelism(2)
            .build();

        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] expected = new byte[32];
        gen.generateBytes(password, expected);

        if (!Arrays.areEqual(expected, key.getEncoded()))
        {
            fail("ARGON2 JCE output does not match lightweight generator");
        }
    }

    private void invalidSpecTest()
        throws Exception
    {
        SecretKeyFactory fact = SecretKeyFactory.getInstance("ARGON2", "BC");

        try
        {
            fact.generateSecret(new javax.crypto.spec.PBEKeySpec("x".toCharArray()));
            fail("non-Argon2 key spec accepted");
        }
        catch (java.security.spec.InvalidKeySpecException e)
        {
            // expected
        }
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new Argon2KeyFactoryTest());
    }
}
