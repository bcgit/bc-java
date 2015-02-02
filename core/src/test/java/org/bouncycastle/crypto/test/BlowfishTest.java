package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * blowfish tester - vectors from http://www.counterpane.com/vectors.txt
 */
public class BlowfishTest
    extends CipherTest
{
    static SimpleTest[]  tests = 
            {
                new BlockCipherVectorTest(0, new BlowfishEngine(),
                        new KeyParameter(Hex.decode("0000000000000000")),
                        "0000000000000000", "4EF997456198DD78"),
                new BlockCipherVectorTest(1, new BlowfishEngine(),
                        new KeyParameter(Hex.decode("FFFFFFFFFFFFFFFF")),
                        "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"),
                new BlockCipherVectorTest(2, new BlowfishEngine(),
                        new KeyParameter(Hex.decode("3000000000000000")),
                        "1000000000000001", "7D856F9A613063F2"),
                new BlockCipherVectorTest(3, new BlowfishEngine(),
                        new KeyParameter(Hex.decode("1111111111111111")),
                        "1111111111111111", "2466DD878B963C9D"),
                new BlockCipherVectorTest(4, new BlowfishEngine(),
                        new KeyParameter(Hex.decode("0123456789ABCDEF")),
                        "1111111111111111", "61F9C3802281B096"),
                new BlockCipherVectorTest(5, new BlowfishEngine(),
                        new KeyParameter(Hex.decode("FEDCBA9876543210")),
                        "0123456789ABCDEF", "0ACEAB0FC6A0A28D"),
                new BlockCipherVectorTest(6, new BlowfishEngine(),
                        new KeyParameter(Hex.decode("7CA110454A1A6E57")),
                        "01A1D6D039776742", "59C68245EB05282B"),
                new BlockCipherVectorTest(7, new BlowfishEngine(),
                        new KeyParameter(Hex.decode("0131D9619DC1376E")),
                        "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"),
            };

    BlowfishTest()
    {
        super(tests, new BlowfishEngine(), new KeyParameter(new byte[16]));
    }

    public String getName()
    {
        return "Blowfish";
    }

    public void performTest()
        throws Exception
    {
        super.performTest();

        testPasswordLengths();
    }

    private void testPasswordLengths()
    {
        BlowfishEngine engine = new BlowfishEngine();

        // 4 byte (32 bit) key is OK
        engine.init(true, new KeyParameter(new byte[4]));

        // < 4 bytes not OK
        try
        {
            engine.init(true, new KeyParameter(new byte[3]));
            fail("< 32 bit key should be disallowed");
        }
        catch (IllegalArgumentException e)
        {
        }

        // 56 byte (448 bit) OK
        engine.init(true, new KeyParameter(new byte[56]));

        // > 56 bytes not OK
        try
        {
            engine.init(true, new KeyParameter(new byte[57]));
            fail("> 448");
        }
        catch (IllegalArgumentException e)
        {
        }

        // Check unrestricted key size version doesn't care
        engine = BlowfishEngine.uncheckedKeySize();

        // < 4 byte is OK
        engine.init(true, new KeyParameter(new byte[4]));

        // 0 byte key is never OK
        try
        {
            engine.init(true, new KeyParameter(new byte[0]));
            fail("0 bit key should be disallowed");
        }
        catch (IllegalArgumentException e)
        {
        }

        // > 56 bytes is OK
        engine.init(true, new KeyParameter(new byte[57]));

    }

    public static void main(
        String[]    args)
    {
        runTest(new BlowfishTest());
    }
}
