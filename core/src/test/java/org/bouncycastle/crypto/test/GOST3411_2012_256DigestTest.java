package org.bouncycastle.crypto.test;

import java.util.ArrayList;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class GOST3411_2012_256DigestTest
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
        "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
        "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50"
    };

    GOST3411_2012_256DigestTest()
    {
        super(new GOST3411_2012_256Digest(), messages, digests);
    }

    public void performTest()
    {
        super.performTest();

        HMac gMac = new HMac(new GOST3411_2012_256Digest());

        gMac.init(new KeyParameter(Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")));

        byte[] data = Hex.decode("0126bdb87800af214341456563780100");

        gMac.update(data, 0, data.length);
        byte[] mac = new byte[gMac.getMacSize()];

        gMac.doFinal(mac, 0);

        if (!Arrays.areEqual(Hex.decode("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"), mac))
        {
            fail("mac calculation failed.");
        }
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new GOST3411_2012_256Digest((GOST3411_2012_256Digest)digest);
    }

    public static void main(String[] args)
    {
        runTest(new GOST3411_2012_256DigestTest());
    }
}
