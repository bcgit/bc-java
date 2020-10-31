package org.bouncycastle.crypto.test;

import java.security.SecureRandom;
import java.util.ArrayList;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class OpenBSDBCryptTest
    extends SimpleTest
{

    private final static String[][] bcryptTest1 = // vectors from http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/glibc/crypt_blowfish/wrapper.c?rev=HEAD
        {
            {"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
                "U*U"},
            {"$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
                "U*U*"},
            {"$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
                "U*U*U"},
            {"$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
                ""},
            {"$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
                "0123456789abcdefghijklmnopqrstuvwxyz"
                    + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                    + "chars after 72 are ignored"},
        };

    private final static String[] bcryptTest2 = { // from: http://openwall.info/wiki/john/sample-hashes
        "$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe", "password"
    };

    private final static String[] bcryptTest2b = { // from: http://stackoverflow.com/questions/11654684/verifying-a-bcrypt-hash
        "$2a$10$.TtQJ4Jr6isd4Hp.mVfZeuh6Gws4rOQ/vdBczhDx.19NFK0Y84Dle", "\u03c0\u03c0\u03c0\u03c0\u03c0\u03c0\u03c0\u03c0"
    };

    private final static String[][] bcryptTest3 = // from: https://bitbucket.org/vadim/bcrypt.net/src/464c41416dc9/BCrypt.Net.Test/TestBCrypt.cs - plain - salt - expected
        {
            {"", "$2a$06$DCq7YPn5Rq63x1Lad4cll.", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."},
            {"", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"},
            {"", "$2a$10$k1wbIrmNyFAPwPVPSVa/ze", "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"},
            {"", "$2a$12$k42ZFHFWqBp3vWli.nIn8u", "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"},
            {"a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"},
            {"a", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."},
            {"a", "$2a$10$k87L/MF28Q673VKh8/cPi.", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"},
            {"a", "$2a$12$8NJH3LsPrANStV6XtBakCe", "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"},
            {"abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"},
            {"abc", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"},
            {"abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"},
            {"abc", "$2a$12$EXRkfkdmXn2gzds2SSitu.", "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"},
            {"abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"},
            {"abcdefghijklmnopqrstuvwxyz", "$2a$08$aTsUwsyowQuzRrDqFflhge", "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."},
            {"abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1u", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"},
            {"abcdefghijklmnopqrstuvwxyz", "$2a$12$D4G5f18o7aMMfwasBL7Gpu", "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"},
            {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"},
            {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262hu", "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"},
            {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"},
            {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"},
        };

    private static final String[][] bcryptTest4 = { // from: https://github.com/ChrisMcKee/cryptsharp/blob/master/Tests/vectors/BCrypt.txt
        {"n6HyjrYTo/r4lgjvM7L<`iM", "$2a$07$XPrYfnqc5ankSHnRfmPVu.A0trKq3VdczdbJjKaWIksKF.GfFCxv."},
        {"~s0quB/K8zRtRT:QtZr`s|^O", "$2a$07$5zzz8omiaStXwOetWwlmuePPRwUt0jhNBPYGGgAMcUDvqsGVqv9Cy"},
        {"r>8y3uE}6<7nI34?Q2rR0JEw", "$2a$07$k5AH9bO9aplPYdZMZ155qOcY1FewMXcupWewW6fViUtsVQ2Umg6LS"},
        {">l_7}xxH3|Cr{dCR[HTUN@k~", "$2a$05$24xz81ZZsMUMm940bbWMCeHsO.s6A3MG0JZzm4y3.Ti6P96bz6RN6"},
        {"D`lCFYTe9_8IW6nEB:oPjEk/S", "$2a$05$bA1xkp4NqFvDmtQJtDO9CugW0INxQLpMZha8AaHmBj9Zg9HlfQtBa"},
        {"UBGYU6|a|RpA:bp[;}p.ZY4f1", "$2a$08$gu4KBnkla.bEqHiwaJ8.z.0ixfzE1Q0/iPfmpfRmUA.NUhUdZboxa"},
        {"O9X[kP6{63F3rXKtN>n?zh2_", "$2a$04$yRZW9xEsqN9DL19jveqFyO1bljZ0r5KNCYqQzMqYpDB7XHWqDWNGC"},
        {":Sa:BknepsG}\\5dOj>kh0KAk", "$2a$04$KhDTFUlakUsPNuLQSgyr7.xQZxkTSIvo0nFw0XyjvrH6n5kZkYDLG"},// extra escape sequence added
        {"2_9J6k:{z?SSjCzL/GT/5CMgc", "$2a$05$eN1jCXDxN9HmuIARJlwH4ewsEyYbAmq7Cw99gEHqGRXtWyrRNLScy"},

        {"2KNy`Kodau14?s8XVru<IIw0eDw|.64MM^Wtv;3sfZt~3`2QN6/U]0^1HtETqWHt<lMfD-LX::zo7AcNLQ.Q.@.g5kX`j7hRi", "$2a$04$xUNE1aUuNlpNwSOuz1VpjuBgW95ImLccIquQxyGLeinucvokg2Ale"},
        {"0yWE>E;h/kdCRd@T]fQiv`Vz]KC0zaIAIeyY4zcooQ0^DfP{hHsw9?atO}CxbkbnK-LxUe;|FiBEluVqO@ysHhXQDdXPt0p", "$2a$07$pNHi/IxrSUohtsD5/eIv4O324ZPGfJE7mUAaNpIPkpyxjW9kqIk76"},
        {"ilWj~2mLBa1Pq`sxrW8fNNq:XF0@KP5RLW9u?[E_wwkROmCSWudYoS5I2HGI-1-?Pd0zVxTIeNbF;nLDUGtce{8dHmx90:;N<8", "$2a$07$ePVgkQl8QKSG2Xv6o0bnOe4SZp4ejag5CP44tjxfmY17F5VzRgwF6"},
        {"dj~OsXmQGj6FXnPGgwg9]G@75~L@G[|e<hgh2vaNqIyYZPh@M;I1DTgZS/~Q:i[6d]oei:hBw4}{}y7k9K^4SoN}wb8mrg[", "$2a$04$BZT7YoAYAgtNkD0/BOl.jOi0dDni7WtmB8.wAebHeHkOs.TpRgml."},
        {"7;PjW]RYJoZXf.r2M^Mm1jVIe0wJ=Kdd2iUBuu1v3HGI1-S[TB6yg{0~:nbpeA08dysS5d}@Oxbrpj[~i-60mpq1WZqQmSVpnR", "$2a$07$fa9NDzoPKiSWC67cP/tj2OqE0PqvGwzRoJiCKj.czyqKyvpdtVpKe"},
        {"8nv;PAN~-FQ]Emh@.TKG=^.t8R0EQC0T?x9|9g4xzxYmSbBO1qDx8kv-ehh0IBv>3KWhz.Z~jUF0tt8[5U@8;5:=[v6pf.IEJ", "$2a$08$eXo9KDc1BZyybBgMurpcD.GA1/ch3XhgBnIH10Xvjc2ogZaGg3t/m"},
    };


    // 2y vectors generated from htpasswd -nB -C 12, nb leading username was removed.
    private static final String[][] twoYVec = new String[][]{
        {"a", "$2y$12$DB3BUbYa/SsEL7kCOVji0OauTkPkB5Y1OeyfxJHM7jvMrbml5sgD2"},
        {"abc", "$2y$12$p.xODEbFcXUlHGbNxWZqAe6AA5FWupqXmN9tZea2ACDhwIx4EA2a6"},
        {"hello world", "$2y$12$wfkxITYXjNLVpEi9nOjz7uXMhCXKSTY7O2y7X4bwY89aGSvRziguq"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXY", "$2y$12$QwAt5kuG68nW7v.87q0QPuwdki3romFc/RU/RV3Qqk4FPw6WdbQzu"}
    };

    // Same as 2y vectors only version changed to 2b to verify handling of that version.
    private static final String[][] twoBVec = new String[][]{
        {"a", "$2b$12$DB3BUbYa/SsEL7kCOVji0OauTkPkB5Y1OeyfxJHM7jvMrbml5sgD2"},
        {"abc", "$2b$12$p.xODEbFcXUlHGbNxWZqAe6AA5FWupqXmN9tZea2ACDhwIx4EA2a6"},
        {"hello world", "$2b$12$wfkxITYXjNLVpEi9nOjz7uXMhCXKSTY7O2y7X4bwY89aGSvRziguq"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXY", "$2b$12$QwAt5kuG68nW7v.87q0QPuwdki3romFc/RU/RV3Qqk4FPw6WdbQzu"}
    };

    private static final String[][] twoVec = new String[][]{
        {"a", "$2$12$DB3BUbYa/SsEL7kCOVji0OauTkPkB5Y1OeyfxJHM7jvMrbml5sgD2"},
        {"abc", "$2$12$p.xODEbFcXUlHGbNxWZqAe6AA5FWupqXmN9tZea2ACDhwIx4EA2a6"},
        {"hello world", "$2$12$wfkxITYXjNLVpEi9nOjz7uXMhCXKSTY7O2y7X4bwY89aGSvRziguq"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXY", "$2$12$QwAt5kuG68nW7v.87q0QPuwdki3romFc/RU/RV3Qqk4FPw6WdbQzu"}
    };

    private static final String[][] twoXVec = new String[][]{
        {"a", "$2x$12$DB3BUbYa/SsEL7kCOVji0OauTkPkB5Y1OeyfxJHM7jvMrbml5sgD2"},
        {"abc", "$2x$12$p.xODEbFcXUlHGbNxWZqAe6AA5FWupqXmN9tZea2ACDhwIx4EA2a6"},
        {"hello world", "$2x$12$wfkxITYXjNLVpEi9nOjz7uXMhCXKSTY7O2y7X4bwY89aGSvRziguq"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXYABCDEFGHIJKLMNOPQRSTUVWXY", "$2x$12$QwAt5kuG68nW7v.87q0QPuwdki3romFc/RU/RV3Qqk4FPw6WdbQzu"}
    };

    public static void main(String[] args)
    {
        runTest(new OpenBSDBCryptTest());
    }

    public String getName()
    {
        return "OpenBSDBCrypt";
    }


    public void testPermutations()
        throws Exception
    {

        byte[] rootPassword = Strings.toByteArray("aabcc");
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
                        String expected = OpenBSDBCrypt.generate(rootPassword, salt, 4);
                        String testValue = OpenBSDBCrypt.generate(candidate, salt, 4);

                        //
                        // If the passwords are the same for the same salt we should have the same string.
                        //
                        boolean sameAsRoot = Arrays.areEqual(rootPassword, candidate);
                        isTrue("expected same result", sameAsRoot == expected.equals(testValue));

                        //
                        // check that the test password passes against itself.
                        //
                        isTrue("candidate valid with self", OpenBSDBCrypt.checkPassword(testValue, candidate));

                        //
                        // Check against expected, it should always track sameAsRoot.
                        //
                        boolean candidateRootValid = OpenBSDBCrypt.checkPassword(expected, candidate);
                        isTrue("candidate valid with root", sameAsRoot == candidateRootValid);
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


    public void performTest()
        throws Exception
    {

        testPermutations();

        byte[] salt = new byte[16];
        for (int i = 0; i < bcryptTest1.length; i++)
        {
            String[] testString = bcryptTest1[i];
            char[] password = testString[1].toCharArray();

            String s1 = OpenBSDBCrypt.generate(password, salt, 4);
            String s2 = OpenBSDBCrypt.generate(Strings.toByteArray(password), salt, 4);

            isEquals(s1, s2);
        }

        for (int i = 0; i < bcryptTest1.length; i++)
        {
            String[] testString = bcryptTest1[i];
            String encoded = testString[0];
            String password = testString[1];
            if (!OpenBSDBCrypt.checkPassword(encoded, password.toCharArray()))
            {
                fail("test1 mismatch: " + "[" + i + "] " + password);
            }
        }

        String encoded = bcryptTest2[0];
        String password = bcryptTest2[1];
        if (!OpenBSDBCrypt.checkPassword(encoded, password.toCharArray()))
        {
            fail("bcryptTest2 mismatch: " + password);
        }


        encoded = bcryptTest2b[0];
        password = bcryptTest2b[1];
        if (!OpenBSDBCrypt.checkPassword(encoded, password.toCharArray()))
        {
            fail("bcryptTest2b mismatch: " + password);
        }


        for (int i = 0; i < bcryptTest3.length; i++)
        {
            String[] testString = bcryptTest3[i];
            encoded = testString[2];
            password = testString[0];
            if (!OpenBSDBCrypt.checkPassword(encoded, password.toCharArray()))
            {
                fail("test3 mismatch: " + "[" + i + "] " + password);
            }
        }

        for (int i = 0; i < bcryptTest4.length; i++)
        {
            String[] testString = bcryptTest4[i];
            encoded = testString[1];
            password = testString[0];
            if (!OpenBSDBCrypt.checkPassword(encoded, password.toCharArray()))
            {
                fail("test4 mismatch: " + "[" + i + "] " + password);
            }
        }

        for (int i = 0; i < twoYVec.length; i++)
        {
            password = twoYVec[i][0];
            encoded = twoYVec[i][1];

            if (!OpenBSDBCrypt.checkPassword(encoded, password.toCharArray()))
            {
                fail("twoYVec mismatch: " + "[" + i + "] " + password);
            }
        }

        oldPrefixTest(twoBVec);

        oldPrefixTest(twoXVec);

        oldPrefixTest(twoVec);

        int costFactor = 4;
        SecureRandom random = new SecureRandom();
        salt = new byte[16];
        for (int i = 0; i < 1000; i++)
        {
            random.nextBytes(salt);
            final String tokenString = OpenBSDBCrypt
                .generate("test-token".toCharArray(), salt, costFactor);

            isTrue(OpenBSDBCrypt.checkPassword(tokenString, "test-token".toCharArray()));
            isTrue(!OpenBSDBCrypt.checkPassword(tokenString, "wrong-token".toCharArray()));
        }
    }

    private void oldPrefixTest(String[][] twoXVec)
    {
        String password;
        String encoded;
        for (int i = 0; i < twoXVec.length; i++)
        {
            password = twoXVec[i][0];
            encoded = twoXVec[i][1];

            if (!OpenBSDBCrypt.checkPassword(encoded, password.toCharArray()))
            {
                fail("twoBVec mismatch: " + "[" + i + "] " + password);
            }
        }

        for (int i = 0; i < twoXVec.length; i++)
        {
            password = twoXVec[i][0];
            encoded = twoXVec[i][1];

            if (!OpenBSDBCrypt.checkPassword(encoded, Strings.toUTF8ByteArray(password)))
            {
                fail("twoBVec mismatch: " + "[" + i + "] " + password);
            }
        }
    }
}

