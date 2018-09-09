package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * CSHAKE test vectors from:
 *
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
 */
public class CSHAKETest
    extends SimpleTest
{
    public String getName()
    {
        return "CSHAKE";
    }

    public void performTest()
        throws Exception
    {
        CSHAKEDigest cshake = new CSHAKEDigest(128, new byte[0], Strings.toByteArray("Email Signature"));

        cshake.update(Hex.decode("00010203"), 0, 4);

        byte[] res = new byte[32];

        cshake.doOutput(res, 0, res.length);

        isTrue(Arrays.areEqual(Hex.decode("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5"), res));

        cshake = new CSHAKEDigest(128, new byte[0], Strings.toByteArray("Email Signature"));

        cshake.update(Hex.decode(
            "000102030405060708090A0B0C0D0E0F" +
                "101112131415161718191A1B1C1D1E1F" +
                "202122232425262728292A2B2C2D2E2F" +
                "303132333435363738393A3B3C3D3E3F" +
                "404142434445464748494A4B4C4D4E4F" +
                "505152535455565758595A5B5C5D5E5F" +
                "606162636465666768696A6B6C6D6E6F" +
                "707172737475767778797A7B7C7D7E7F" +
                "808182838485868788898A8B8C8D8E8F" +
                "909192939495969798999A9B9C9D9E9F" +
                "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
                "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
                "C0C1C2C3C4C5C6C7"), 0, 1600 / 8);

        res = new byte[32];

        cshake.doOutput(res, 0, res.length);

        isTrue(Arrays.areEqual(Hex.decode("C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B "), res));

        cshake = new CSHAKEDigest(256, new byte[0], Strings.toByteArray("Email Signature"));

        cshake.update(Hex.decode("00010203"), 0, 4);

        res = new byte[64];

        cshake.doOutput(res, 0, res.length);

        isTrue(Arrays.areEqual(Hex.decode(
        "D008828E2B80AC9D2218FFEE1D070C48"+
            "B8E4C87BFF32C9699D5B6896EEE0EDD1"+
            "64020E2BE0560858D9C00C037E34A969"+
            "37C561A74C412BB4C746469527281C8C"),res));

        cshake = new CSHAKEDigest(256, new byte[0], Strings.toByteArray("Email Signature"));

        cshake.update(Hex.decode(
            "000102030405060708090A0B0C0D0E0F" +
                "101112131415161718191A1B1C1D1E1F" +
                "202122232425262728292A2B2C2D2E2F" +
                "303132333435363738393A3B3C3D3E3F" +
                "404142434445464748494A4B4C4D4E4F" +
                "505152535455565758595A5B5C5D5E5F" +
                "606162636465666768696A6B6C6D6E6F" +
                "707172737475767778797A7B7C7D7E7F" +
                "808182838485868788898A8B8C8D8E8F" +
                "909192939495969798999A9B9C9D9E9F" +
                "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
                "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
                "C0C1C2C3C4C5C6C7"), 0, 1600 / 8);

        res = new byte[64];

        cshake.doOutput(res, 0, res.length);

        isTrue(Arrays.areEqual(Hex.decode(
                "07DC27B11E51FBAC75BC7B3C1D983E8B"+
                    "4B85FB1DEFAF218912AC864302730917"+
                    "27F42B17ED1DF63E8EC118F04B23633C"+
                    "1DFB1574C8FB55CB45DA8E25AFB092BB"), res));
    }

    public static void main(
        String[] args)
    {
        runTest(new CSHAKETest());
    }
}
