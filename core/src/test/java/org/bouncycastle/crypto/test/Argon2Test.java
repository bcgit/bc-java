package org.bouncycastle.crypto.test;


import java.util.ArrayList;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests from https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03
 */
public class Argon2Test
    extends SimpleTest
{
    private static final int DEFAULT_OUTPUTLEN = 32;

    public String getName()
    {
        return "ArgonTest";
    }

    public void performTest()
        throws Exception
    {
        if (getJvmVersion() < 7)
        {
            return;
        }

        testPermutations();
        testVectorsFromInternetDraft();

        int version = Argon2Parameters.ARGON2_VERSION_10;



        /* Multiple test cases for various input values */
        hashTest(version, 2, 16, 1, "password", "somesalt",
            "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 20, 1, "password", "somesalt",
            "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
            DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 18, 1, "password", "somesalt",
            "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
            DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 8, 1, "password", "somesalt",
            "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
            DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 8, 2, "password", "somesalt",
            "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb", DEFAULT_OUTPUTLEN);
        hashTest(version, 1, 16, 1, "password", "somesalt",
            "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2", DEFAULT_OUTPUTLEN);
        hashTest(version, 4, 16, 1, "password", "somesalt",
            "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b", DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 16, 1, "differentpassword", "somesalt",
            "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3", DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 16, 1, "password", "diffsalt",
            "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 16, 1, "password", "diffsalt",
            "1a097a5d1c80e579583f6e19c7e4763ccb7c522ca85b7d58143738e12ca39f8e6e42734c950ff2463675b97c37ba" +
                "39feba4a9cd9cc5b4c798f2aaf70eb4bd044c8d148decb569870dbd923430b82a083f284beae777812cce18cdac68ee8ccef" +
                "c6ec9789f30a6b5a034591f51af830f4",
            112);


        version = Argon2Parameters.ARGON2_VERSION_13;


        /* Multiple test cases for various input values */
        hashTest(version, 2, 16, 1, "password", "somesalt",
            "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
            DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 20, 1, "password", "somesalt",
            "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 18, 1, "password", "somesalt",
            "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 8, 1, "password", "somesalt",
            "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 8, 2, "password", "somesalt",
            "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61", DEFAULT_OUTPUTLEN);
        hashTest(version, 1, 16, 1, "password", "somesalt",
            "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf", DEFAULT_OUTPUTLEN);
        hashTest(version, 4, 16, 1, "password", "somesalt",
            "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b", DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 16, 1, "differentpassword", "somesalt",
            "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee", DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 16, 1, "password", "diffsalt",
            "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271", DEFAULT_OUTPUTLEN);

    }


    public void testPermutations()
        throws Exception
    {

        byte[] rootPassword = Strings.toByteArray("aac");
        byte[] buf = null;

        byte[][] salts = new byte[3][];

        salts[0] = new byte[16];
        salts[1] = new byte[16];
        salts[2] = new byte[16];
        for (int t = 0; t < 16; t++)
        {
            salts[1][t] = (byte)t;
            salts[2][t] = (byte)(16 - t);
        }


        //
        // Permutation, starting with a shorter array, same length then one longer.
        //
        for (int j = rootPassword.length - 1; j < rootPassword.length + 2; j++)
        {
            buf = new byte[j];

            for (int a = 0; a < rootPassword.length; a++)
            {
                for (int b = 0; b < buf.length; b++)
                {
                    buf[b] = rootPassword[(a + b) % rootPassword.length];
                }


                ArrayList<byte[]> permutations = new ArrayList<byte[]>();
                permute(permutations, buf, 0, buf.length - 1);

                for (int i = 0; i != permutations.size(); i++)
                {
                    byte[] candidate = (byte[])permutations.get(i);
                    for (int k = 0; k != salts.length; k++)
                    {
                        byte[] salt = salts[k];
                        byte[] expected = generate(Argon2Parameters.ARGON2_VERSION_10, 1, 8, 2, rootPassword, salt, 32);
                        byte[] testValue = generate(Argon2Parameters.ARGON2_VERSION_10, 1, 8, 2, candidate, salt, 32);

                        //
                        // If the passwords are the same for the same salt we should have the same string.
                        //
                        boolean sameAsRoot = Arrays.areEqual(rootPassword, candidate);
                        isTrue("expected same result", sameAsRoot == Arrays.areEqual(expected, testValue));

                    }

                }
            }
        }
    }

    private void swap(byte[] buf, int i, int j)
    {
        byte b = buf[i];
        buf[i] = buf[j];
        buf[j] = b;
    }

    private void permute(ArrayList<byte[]> permutation, byte[] a, int l, int r)
    {
        if (l == r)
        {
            permutation.add(Arrays.clone(a));
        }
        else
        {

            for (int i = l; i <= r; i++)
            {
                // Swapping done
                swap(a, l, i);

                // Recursion called
                permute(permutation, a, l + 1, r);

                //backtrack
                swap(a, l, i);
            }
        }
    }


    private byte[] generate(int version, int iterations, int memory, int parallelism,
                            byte[] password, byte[] salt, int outputLength)
    {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i)
            .withVersion(version)
            .withIterations(iterations)
            .withMemoryPowOfTwo(memory)
            .withParallelism(parallelism)
            .withSalt(salt);

        //
        // Set the password.
        //
        Argon2BytesGenerator gen = new Argon2BytesGenerator();

        gen.init(builder.build());

        byte[] result = new byte[outputLength];

        gen.generateBytes(password, result, 0, result.length);
        return result;
    }


    private void hashTest(int version, int iterations, int memory, int parallelism,
                          String password, String salt, String passwordRef, int outputLength)
    {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i)
            .withVersion(version)
            .withIterations(iterations)
            .withMemoryPowOfTwo(memory)
            .withParallelism(parallelism)
            .withSalt(Strings.toByteArray(salt));

        //
        // Set the password.
        //
        Argon2BytesGenerator gen = new Argon2BytesGenerator();

        gen.init(builder.build());

        byte[] result = new byte[outputLength];

        gen.generateBytes(password.toCharArray(), result, 0, result.length);
        isTrue(passwordRef + " Failed", areEqual(result, Hex.decode(passwordRef)));

        Arrays.clear(result);

        // Should be able to re-use generator after successful use
        gen.generateBytes(password.toCharArray(), result, 0, result.length);
        isTrue(passwordRef + " Failed", areEqual(result, Hex.decode(passwordRef)));
    }


    /**
     * Tests from https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03
     *
     * @throws Exception
     */
    private void testVectorsFromInternetDraft()
    {
        byte[] ad = Hex.decode("040404040404040404040404");
        byte[] secret = Hex.decode("0303030303030303");
        byte[] salt = Hex.decode("02020202020202020202020202020202");
        byte[] password = Hex.decode("0101010101010101010101010101010101010101010101010101010101010101");

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_d)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13) // 19
            .withIterations(3)
            .withMemoryAsKB(32)
            .withParallelism(4)
            .withAdditional(ad)
            .withSecret(secret)
            .withSalt(salt);

        Argon2BytesGenerator dig = new Argon2BytesGenerator();

        dig.init(builder.build());

        byte[] result = new byte[32];
        dig.generateBytes(password, result);
        isTrue("Argon 2d Failed", areEqual(result, Hex.decode("512b391b6f1162975371d30919734294f" +
            "868e3be3984f3c1a13a4db9fabe4acb")));


        builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13) // 19
            .withIterations(3)
            .withMemoryAsKB(32)
            .withParallelism(4)
            .withAdditional(ad)
            .withSecret(secret)
            .withSalt(salt);

        dig = new Argon2BytesGenerator();

        dig.init(builder.build());

        result = new byte[32];
        dig.generateBytes(password, result);
        isTrue("Argon 2i Failed", areEqual(result, Hex.decode("c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016" +
            "dd388d29952a4c4672b6ce8")));


        builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13) // 19
            .withIterations(3)
            .withMemoryAsKB(32)
            .withParallelism(4)
            .withAdditional(ad)
            .withSecret(secret)
            .withSalt(salt);

        dig = new Argon2BytesGenerator();

        dig.init(builder.build());

        result = new byte[32];
        dig.generateBytes(password, result);
        isTrue("Argon 2id Failed", areEqual(result, Hex.decode("0d640df58d78766c08c037a34a8b53c9d01ef0452" +
            "d75b65eb52520e96b01e659")));

    }

    private static int getJvmVersion()
    {
        String version = System.getProperty("java.specification.version");
        if (null == version)
        {
            return -1;
        }
        String[] parts = version.split("\\.");
        if (parts == null || parts.length < 1)
        {
            return -1;
        }
        try
        {
            int major = Integer.parseInt(parts[0]);
            if (major == 1 && parts.length > 1)
            {
                return Integer.parseInt(parts[1]);
            }
            return major;
        }
        catch (NumberFormatException e)
        {
            return -1;
        }
    }

    public static void main(String[] args)
    {
        runTest(new Argon2Test());
    }

}
