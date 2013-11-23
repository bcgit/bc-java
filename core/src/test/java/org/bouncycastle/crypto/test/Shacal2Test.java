package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.Shacal2Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Shacal2 tester - vectors from https://www.cosic.esat.kuleuven.be/nessie/testvectors/
 */
public class Shacal2Test
    extends CipherTest
{
    static SimpleTest[]  tests =
            {
                // set 8.0
                new BlockCipherVectorTest(0, new Shacal2Engine(),
                        new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F" +
                            "101112131415161718191A1B1C1D1E1F" +
                            "202122232425262728292A2B2C2D2E2F" +
                            "303132333435363738393A3B3C3D3E3F")),
                        "98BCC10405AB0BFC686BECECAAD01AC1" +
                        "9B452511BCEB9CB094F905C51CA45430",
                        "00112233445566778899AABBCCDDEEFF" +
                        "102132435465768798A9BACBDCEDFE0F"),
                // set 8.1
                new BlockCipherVectorTest(1, new Shacal2Engine(),
                        new KeyParameter(Hex.decode("2BD6459F82C5B300952C49104881FF48" +
                            "2BD6459F82C5B300952C49104881FF48" +
                            "2BD6459F82C5B300952C49104881FF48" +
                            "2BD6459F82C5B300952C49104881FF48")),
                            "481F122A75F2C4C3395140B5A951EBBA" +
                            "06D96BDFD9D8FF4FB59CBD1287808D5A",
                            "EA024714AD5C4D84EA024714AD5C4D84" +
                            "EA024714AD5C4D84EA024714AD5C4D84"),
                 // 7.255
                new BlockCipherVectorTest(2, new Shacal2Engine(),
                        new KeyParameter(Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")),
                            "94FEDFF2A0CFE3C983D340C88D73F8CF" +
                            "4B79FC581797EC10B27D4DA1B51E1BC7",
                            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
                // 7.100
                new BlockCipherVectorTest(3, new Shacal2Engine(),
                        new KeyParameter(Hex.decode("64646464646464646464646464646464" +
                            "64646464646464646464646464646464" +
                            "64646464646464646464646464646464" +
                            "64646464646464646464646464646464")),
                            "6643CB84B3B3F126F5E50959EF4CE73D" +
                            "B8500918ABE1056368DB06CA8C1C0D45",
                            "64646464646464646464646464646464" +
                            "64646464646464646464646464646464"),
                // 7.50
                new BlockCipherVectorTest(4, new Shacal2Engine(),
                        new KeyParameter(Hex.decode("32323232323232323232323232323232" +
                            "32323232323232323232323232323232" +
                            "32323232323232323232323232323232" +
                            "32323232323232323232323232323232")),
                            "92E937285AB11FE3561542C43C918966" +
                            "971DE722E9B9D38BD69EAC77899DCF81",
                            "32323232323232323232323232323232" +
                            "32323232323232323232323232323232"),
                // 7.0
                new BlockCipherVectorTest(5, new Shacal2Engine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000" +
                            "00000000000000000000000000000000" +
                            "00000000000000000000000000000000" +
                            "00000000000000000000000000000000")),
                            "F8C9259FA4F5D787B570AFA9219166A6" +
                            "3636FC5C30AC289155D0CC4FFCB4B03D",
                            "00000000000000000000000000000000" +
                            "00000000000000000000000000000000"),
                // 6.255
                new BlockCipherVectorTest(6, new Shacal2Engine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000" +
                            "00000000000000000000000000000000" +
                            "00000000000000000000000000000000" +
                            "00000000000000000000000000000000")),
                            "F4E976DF0172CD961D4C8D466A12F676" +
                            "5B9089046E747CD2A41BF43C18A8328E",
                            "00000000000000000000000000000000" +
                            "00000000000000000000000000000001"),
                // 6.100
                new BlockCipherVectorTest(7, new Shacal2Engine(),
                    new KeyParameter(Hex.decode("00000000000000000000000000000000" +
                        "00000000000000000000000000000000" +
                        "00000000000000000000000000000000" +
                        "00000000000000000000000000000000")),
                        "3B929F0597E21D0076EC399D21B67713" +
                        "B40E3AD559704219A26A3380212D5AD6",
                        "00000000000000000000000008000000" +
                        "00000000000000000000000000000000"),

                // 6.0
                new BlockCipherVectorTest(8, new Shacal2Engine(),
                    new KeyParameter(Hex.decode("00000000000000000000000000000000" +
                        "00000000000000000000000000000000" +
                        "00000000000000000000000000000000" +
                        "00000000000000000000000000000000")),
                        "43A0DAD8307F19FBBCF166FE20BAC075" +
                        "C56FF14042550E472094B042BE5963EE",
                        "80000000000000000000000000000000" +
                        "00000000000000000000000000000000"),
            };

    Shacal2Test()
    {
        super(tests, new Shacal2Engine(), new KeyParameter(new byte[16]));
    }

    public void performTest()
        throws Exception
    {
        super.performTest();

        // 1.0
        iteratedTest(0,
            Hex.decode("80000000000000000000000000000000" +
            "00000000000000000000000000000000" +
            "00000000000000000000000000000000" +
            "00000000000000000000000000000000"),
            Hex.decode("00000000000000000000000000000000" +
            "00000000000000000000000000000000"),
            Hex.decode("361AB6322FA9E7A7BB23818D839E01BD" +
                "DAFDF47305426EDD297AEDB9F6202BAE"),
            Hex.decode("226A582DE04383D0F3E7DE655DD848AC" +
            "3E14CCFB4E76F7B7069879F67C4D5420"),
            Hex.decode("B05D5A18C0712082CFF5BA9DBBCD7269" +
            "114FC3DF83B42DAC306D95BBC473D839"));

        // 1.100
        iteratedTest(1,
            Hex.decode("00000000000000000000000008000000" +
                "00000000000000000000000000000000" +
                "00000000000000000000000000000000" +
                "00000000000000000000000000000000"),
            Hex.decode("00000000000000000000000000000000" +
            "00000000000000000000000000000000"),
            Hex.decode("F703282E54592A5617E10618027BB67F" +
                "639E43A90767150D8B7F5E83054B3CBD"),
            Hex.decode("3B442692B579485B8BA2F92CE3B90DE7" +
                "D2EA03D8B3C8E7BE7BF6415F798EED90"),
            Hex.decode("331B9B65F06230380BBEECFBFBA94BCF" +
                "92AF6341F815D7651F996144A5377263"));
    }

    private void iteratedTest(int index, byte[] key, byte[] plain, byte[] cipher, byte[] cipher100, byte[] cipher1000)
    {
        BlockCipher engine = new Shacal2Engine();

        engine.init(true, new KeyParameter(key));

        byte[] buf = new byte[plain.length];

        System.arraycopy(plain, 0, buf, 0, plain.length);

        engine.processBlock(buf, 0, buf, 0);

        if (!Arrays.areEqual(cipher, buf))
        {
            fail(index + " single count failed");
        }

        for (int i = 1; i != 100; i++)
        {
            engine.processBlock(buf, 0, buf, 0);
        }

        if (!Arrays.areEqual(cipher100, buf))
        {
            fail(index + " 100 count failed");
        }

        for (int i = 100; i != 1000; i++)
        {
            engine.processBlock(buf, 0, buf, 0);
        }

        if (!Arrays.areEqual(cipher1000, buf))
        {
            fail(index + " 1000 count failed");
        }
    }

    public String getName()
    {
        return "Shacal2";
    }

    public static void main(
        String[]    args)
    {
        runTest(new Shacal2Test());
    }
}
