package org.bouncycastle.crypto.test;

import java.util.ArrayList;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class GOST3411_2012_512DigestTest
    extends DigestTest
{
    private static final String[] messages;

    private static char[] M1 =
        {
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x30, 0x31, 0x32
        };

    private static char[] M2=
        {
            0xd1,0xe5,0x20,0xe2,0xe5,0xf2,0xf0,0xe8,0x2c,0x20,0xd1,0xf2,0xf0,0xe8,0xe1,0xee,0xe6,0xe8,0x20,0xe2,
            0xed,0xf3,0xf6,0xe8,0x2c,0x20,0xe2,0xe5,0xfe,0xf2,0xfa,0x20,0xf1,0x20,0xec,0xee,0xf0,0xff,0x20,0xf1,
            0xf2,0xf0,0xe5,0xeb,0xe0,0xec,0xe8,0x20,0xed,0xe0,0x20,0xf5,0xf0,0xe0,0xe1,0xf0,0xfb,0xff,0x20,0xef,
            0xeb,0xfa,0xea,0xfb,0x20,0xc8,0xe3,0xee,0xf0,0xe5,0xe2,0xfb
        };

    static
    {
        ArrayList<String> strList = new ArrayList<String>();

        strList.add(new String(M1));
        strList.add(new String(M2));
        messages = new String[strList.size()];
        for (int i = 0; i < strList.size(); i++)
        {
            messages[i] = (String)strList.get(i);
        }
    }

    private static final String[] digests = {
        "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48",
        "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28",
    };

    public GOST3411_2012_512DigestTest()
    {
        super(new GOST3411_2012_512Digest(), messages, digests);
    }

    public void performTest()
    {
        super.performTest();

        HMac gMac = new HMac(new GOST3411_2012_512Digest());

        gMac.init(new KeyParameter(Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")));

        byte[] data = Hex.decode("0126bdb87800af214341456563780100");

        gMac.update(data, 0, data.length);
        byte[] mac = new byte[gMac.getMacSize()];

        gMac.doFinal(mac, 0);

        if (!Arrays.areEqual(Hex.decode("a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"), mac))
        {
            fail("mac calculation failed.");
        }
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new GOST3411_2012_512Digest((GOST3411_2012_512Digest)digest);
    }

    public static void main(String[] args)
    {
        runTest(new GOST3411_2012_512DigestTest());
    }
}
