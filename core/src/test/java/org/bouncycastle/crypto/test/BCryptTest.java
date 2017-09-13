package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/*
 * bcrypt test vectors
 */
public class BCryptTest
    extends SimpleTest
{
    // Raw test vectors based on crypt style test vectors
    // Cross checked with JBCrypt
    private static final Object[][] testVectors = {
        {"", "144b3d691a7b4ecf39cf735c7fa7a79c", Integers.valueOf(6), "557e94f34bf286e8719a26be94ac1e16d95ef9f819dee092"},
        {"00", "144b3d691a7b4ecf39cf735c7fa7a79c", Integers.valueOf(6), "557e94f34bf286e8719a26be94ac1e16d95ef9f819dee092"},
        {"00", "26c63033c04f8bcba2fe24b574db6274", Integers.valueOf(8), "56701b26164d8f1bc15225f46234ac8ac79bf5bc16bf48ba"},
        {"00", "9b7c9d2ada0fd07091c915d1517701d6", Integers.valueOf(10), "7b2e03106a43c9753821db688b5cc7590b18fdf9ba544632"},
        {"6100", "a3612d8c9a37dac2f99d94da03bd4521", Integers.valueOf(6), "e6d53831f82060dc08a2e8489ce850ce48fbf976978738f3"},
        {"6100", "7a17b15dfe1c4be10ec6a3ab47818386", Integers.valueOf(8), "a9f3469a61cbff0a0f1a1445dfe023587f38b2c9c40570e1"},
        {"6100", "9bef4d04e1f8f92f3de57323f8179190", Integers.valueOf(10), "5169fd39606d630524285147734b4c981def0ee512c3ace1"},
        {"61626300", "2a1f1dc70a3d147956a46febe3016017", Integers.valueOf(6), "d9a275b493bcbe1024b0ff80d330253cfdca34687d8f69e5"},
        {"61626300", "4ead845a142c9bc79918c8797f470ef5", Integers.valueOf(8), "8d4131a723bfbbac8a67f2e035cae08cc33b69f37331ea91"},
        {"61626300", "631c554493327c32f9c26d9be7d18e4c", Integers.valueOf(10), "8cd0b863c3ff0860e31a2b42427974e0283b3af7142969a6"},
        {"6162636465666768696a6b6c6d6e6f707172737475767778797a00", "02d1176d74158ee29cffdac6150cf123", Integers.valueOf(6), "4d38b523ce9dc6f2f6ff9fb3c2cd71dfe7f96eb4a3baf19f"},
        {"6162636465666768696a6b6c6d6e6f707172737475767778797a00", "715b96caed2ac92c354ed16c1e19e38a", Integers.valueOf(8), "98bf9ffc1f5be485f959e8b1d526392fbd4ed2d5719f506b"},
        {"6162636465666768696a6b6c6d6e6f707172737475767778797a00", "85727e838f9049397fbec90566ede0df", Integers.valueOf(10), "cebba53f67bd28af5a44c6707383c231ac4ef244a6f5fb2b"},
        {"7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400", "8512ae0d0fac4ec9a5978f79b6171028", Integers.valueOf(6), "26f517fe5345ad575ba7dfb8144f01bfdb15f3d47c1e146a"},
        {"7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400", "1ace2de8807df18c79fced54678f388f", Integers.valueOf(8), "d51d7cdf839b91a25758b80141e42c9f896ae80fd6cd561f"},
        {"7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400", "36285a6267751b14ba2dc989f6d43126", Integers.valueOf(10), "db4fab24c1ff41c1e2c966f8b3d6381c76e86f52da9e15a9"},
        {"c2a300", "144b3d691a7b4ecf39cf735c7fa7a79c", Integers.valueOf(6), "5a6c4fedb23980a7da9217e0442565ac6145b687c7313339"},
    };

    public String getName()
    {
        return "BCrypt";
    }

    public void performTest()
        throws Exception
    {
        testParameters();
        testShortKeys();
        testVectors();
    }

    private void testShortKeys()
    {
        byte[] salt = new byte[16];

        // Check BCrypt with empty key pads to zero byte key
        byte[] hashEmpty = BCrypt.generate(new byte[0], salt, 4);
        byte[] hashZero1 = BCrypt.generate(new byte[1], salt, 4);

        if (!Arrays.areEqual(hashEmpty, hashZero1))
        {
            fail("Hash for empty password should equal zeroed key", new String(Hex.encode(hashEmpty)),
                new String(Hex.encode(hashZero1)));
        }

        // Check zeroed byte key of min Blowfish length is equivalent
        byte[] hashZero4 = BCrypt.generate(new byte[4], salt, 4);
        if (!Arrays.areEqual(hashEmpty, hashZero4))
        {
            fail("Hash for empty password should equal zeroed key[4]", new String(Hex.encode(hashEmpty)), new String(
                Hex.encode(hashZero4)));
        }

        // Check BCrypt isn't padding too small (32 bit) keys
        byte[] hashA = BCrypt.generate(new byte[]{(byte)'a'}, salt, 4);
        byte[] hashA0 = BCrypt.generate(new byte[]{(byte)'a', (byte)0}, salt, 4);
        if (Arrays.areEqual(hashA, hashA0))
        {
            fail("Small keys should not be 0 padded.");
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
        checkIllegal("Salt too small", new byte[1], new byte[15], 4);
        checkIllegal("Salt too big", new byte[1], new byte[17], 4);
        checkIllegal("Cost too low", new byte[16], new byte[16], 3);
        checkIllegal("Cost too high", new byte[16], new byte[16], 32);
        checkIllegal("Passcode too long", new byte[73], new byte[16], 32);
    }

    private void checkOK(String msg, byte[] pass, byte[] salt, int cost)
    {
        try
        {
            BCrypt.generate(pass, salt, cost);
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
            BCrypt.generate(pass, salt, cost);
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
            byte[] password = Hex.decode((String)testVectors[i][0]);
            byte[] salt = Hex.decode((String)testVectors[i][1]);
            int cost = ((Integer)testVectors[i][2]).intValue();
            byte[] expected = Hex.decode((String)testVectors[i][3]);

            test(password, salt, cost, expected);
        }

        isTrue(areEqual(BCrypt.generate(BCrypt.passwordToByteArray("12341234".toCharArray()), Hex.decode("01020304050607080102030405060708"), 5), Hex.decode("cdd19088721c50e5cb49a7b743d93b5a6e67bef0f700cd78")));
        isTrue(areEqual(BCrypt.generate(BCrypt.passwordToByteArray("1234".toCharArray()), Hex.decode("01020304050607080102030405060708"), 5), Hex.decode("02a3269aca2732484057b40c614204814cbfc2becd8e093e")));
    }

    private void test(byte[] password, byte[] salt, int cost, byte[] expected)
    {
        byte[] hash = BCrypt.generate(password, salt, cost);
        if (!Arrays.areEqual(hash, expected))
        {
            fail("Hash for " + new String(Hex.encode(password)), new String(Hex.encode(expected)),
                new String(Hex.encode(hash)));
        }
    }

    public static void main(String[] args)
    {
        runTest(new BCryptTest());
    }
}