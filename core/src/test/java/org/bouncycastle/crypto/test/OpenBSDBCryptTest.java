package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.OpenBSDBcrypt;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/*
 * OpenBSD style bcrypt test vectors
 */
public class OpenBSDBCryptTest
    extends SimpleTest
{
    // Test vectors from JBCrypt, cross-checked with crypt_blowfish
    private static String[][] testVectors = {
            { "",                                   "$2a$06$DCq7YPn5Rq63x1Lad4cll.",    "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." },
            { "",                                   "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",    "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye" },
            { "",                                   "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",    "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW" },
//            { "",                                   "$2a$12$k42ZFHFWqBp3vWli.nIn8u",    "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO" },
            { "a",                                  "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" },
            { "a",                                  "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",    "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V." },
            { "a",                                  "$2a$10$k87L/MF28Q673VKh8/cPi.",    "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u" },
//            { "a",                                  "$2a$12$8NJH3LsPrANStV6XtBakCe",    "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS" },
            { "abc",                                "$2a$06$If6bvum7DFjUnE9p2uDeDu",    "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" },
            { "abc",                                "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",    "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm" },
            { "abc",                                "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",    "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi" },
//            { "abc",                                "$2a$12$EXRkfkdmXn2gzds2SSitu.",    "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q" },
            { "abcdefghijklmnopqrstuvwxyz",         "$2a$06$.rCVZVOThsIa97pEDOxvGu",    "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" },
            { "abcdefghijklmnopqrstuvwxyz",         "$2a$08$aTsUwsyowQuzRrDqFflhge",    "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz." },
            { "abcdefghijklmnopqrstuvwxyz",         "$2a$10$fVH8e28OQRj9tqiDXs1e1u",    "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq" },
//            { "abcdefghijklmnopqrstuvwxyz",         "$2a$12$D4G5f18o7aMMfwasBL7Gpu",    "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.",    "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262hu",    "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",    "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS" },
//            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO",    "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" },
            { "\u00a3"                            , "$2a$06$DCq7YPn5Rq63x1Lad4cll.",    "$2a$06$DCq7YPn5Rq63x1Lad4cll.UkvN5ZG3eIdYifdePATjpEDDrmdFKRK" },
        };

    // Test vectors from crypt_blowfish, not including tests for 2x mode and 'safe' 2a mode.
    // http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/glibc/crypt_blowfish/wrapper.c
    private static Object[][] crypt_blowfishVectors = {
            {"U*U","$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"},
            {"U*U*","$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"},
            {"U*U*U","$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"},
            {"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789","$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"},
            {Hex.decode("ffffa3"),"$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"},
            {Hex.decode("a3"),"$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},
            {Hex.decode("a3"),"$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},
            {Hex.decode("ffa33334ffffffa3333435"),"$2y$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi"},
            {Hex.decode("ffa3333435"),"$2y$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e"},
            {Hex.decode("ffa3333435"),"$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e"},
            {Hex.decode("a36162"),"$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS"},
            {Hex.decode("a36162"),"$2y$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS"},
            {Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                "$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6"},
            {Hex.decode("aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55a"
                + "a55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55"),
                "$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy"},
            {Hex.decode("55aaff55aaff55aaff55aaff55aaff55aaff55aaff55aaff55aaff55aaff55aaff55a"
                + "aff55aaff55aaff55aaff55aaff55aaff55aaff55aaff55aaff55aaff55aaff55aaff55aaff"),
                "$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe"},
            {"","$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"},
        };

    public String getName()
    {
        return "OpenBSDBCrypt";
    }

    public void performTest()
        throws Exception
    {
        testParameters();
        testSaltGeneration();
        testVectors();
        testCryptBlowfishVectors();
    }

    public void testSaltGeneration()
    {
        try
        {
            OpenBSDBcrypt.encodeSalt(new byte[15], 4);
            fail("Salt size for encode");
        }
        catch (IllegalArgumentException e)
        {
        }

        final byte[] salt = Hex.decode("000102030405060708090a0b0c0d0e0f");
        String encodedSalt = OpenBSDBcrypt.encodeSalt(salt, 4);
        if (!encodedSalt.equals("$2a$04$..CA.uOD/eaGAOmJB.yMBu"))
        {
            fail("Salt encoding : ", "$2a$04$..CA.uOD/eaGAOmJB.yMBu", encodedSalt);
        }

        SecureRandom r = new SecureRandom() {
            @Override
            public synchronized void nextBytes(byte[] bytes)
            {
                System.arraycopy(salt, 0, bytes, 0, bytes.length);
            }
        };

        String generatedSalt = OpenBSDBcrypt.generateSalt(4, r);
        if (!generatedSalt.equals("$2a$04$..CA.uOD/eaGAOmJB.yMBu"))
        {
            fail("Salt generation : ", "$2a$04$..CA.uOD/eaGAOmJB.yMBu", generatedSalt);
        }

        String generatedSalt2 = OpenBSDBcrypt.generateSalt(10);
        if (!generatedSalt2.startsWith("$2a$10") || generatedSalt2.length() == 28)
        {
            fail("Generated salt format: " + generatedSalt2);
        }

    }

    public void testParameters()
    {
        checkOK("Empty key", new byte[0], new byte[16], 4);
        checkOK("Minimal values", new byte[1], new byte[16], 4);
        // checkOK("Max cost", new byte[1], new byte[16], 31);
        checkOK("Max passcode", new byte[72], new byte[16], 4);
        checkIllegal("Null password", null, new byte[16], 4);
        checkIllegal("Null salt", new byte[1], null, 4);
        checkIllegal("Null salt", new byte[1], null);
        checkIllegal("Salt too small", new byte[1], new byte[15], 4);
        checkIllegal("Salt too big", new byte[1], new byte[17], 4);
        checkIllegal("Cost too low", new byte[16], new byte[16], 3);
        checkIllegal("Cost too high", new byte[16], new byte[16], 32);
        checkIllegal("Passcode too long", new byte[73], new byte[16], 32);
    }

    private void checkOK(String msg, byte[] pass, byte[] salt, int cost)
    {
        String encodedSalt = (salt == null) ? null : OpenBSDBcrypt.encodeSalt(salt, cost);
        checkOK(msg, pass, encodedSalt);
    }

    private void checkOK(String msg, byte[] pass, String encodedSalt)
    {
        try
        {
            OpenBSDBcrypt.hash(pass, encodedSalt);
        }
        catch (IllegalArgumentException e)
        {
            e.printStackTrace();
            fail(msg);
        }
    }

    private void checkIllegal(String msg, byte[] pass, byte[] salt, int cost)
    {
        try
        {
            String encodedSalt = OpenBSDBcrypt.encodeSalt(salt, cost);
            OpenBSDBcrypt.hash(pass, encodedSalt);
            fail(msg);
        }
        catch (IllegalArgumentException e)
        {
            // e.printStackTrace();
        }
    }

    private void checkIllegal(String msg, byte[] pass, String encodedSalt)
    {
        try
        {
            OpenBSDBcrypt.hash(pass, encodedSalt);
            fail(msg);
        }
        catch (IllegalArgumentException e)
        {
            // e.printStackTrace();
        }
    }

    public void testVectors()
        throws Exception
    {
        for (int i = 0; i < testVectors.length; i++)
        {
            String plain = testVectors[i][0];
            String salt = testVectors[i][1];
            String expected = testVectors[i][2];

            test(plain, salt, expected);

            // Check salt as prefix of hash works the same
            test(plain, expected, expected);
        }
    }

    public void testCryptBlowfishVectors()
    {
        for (int i = 0; i < crypt_blowfishVectors.length; i++)
        {
            Object plain = crypt_blowfishVectors[i][0];
            String expected = (String)crypt_blowfishVectors[i][1];

            if (plain instanceof String)
            {
                test((String)plain, expected, expected);
            }
            else
            {
                test((byte[])plain, expected);
            }
        }
    }

    private void test(byte[] password, String expected)
    {
        String hash = OpenBSDBcrypt.hash(password, expected);
        if (!hash.equals(expected))
        {
            fail("Hash mismatch: " + new String(Hex.encode(password)), expected, hash);
        }
        if (!OpenBSDBcrypt.verify(password, expected))
        {
            fail("Hash verify failed: " + new String(Hex.encode(password)), expected, hash);
        }
    }

    private void test(String password, String salt, String expected)
    {
        String hash = OpenBSDBcrypt.hash(password, salt);
        if (!hash.equals(expected))
        {
            fail("Hash mismatch: " + password, expected, hash);
        }
        if (!OpenBSDBcrypt.verify(password, expected))
        {
            fail("Hash verify failed: " + password, expected, hash);
        }
    }

    public static void main(String[] args)
    {
        runTest(new OpenBSDBCryptTest());
    }
}
