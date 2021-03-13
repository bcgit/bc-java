package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.ParallelHash;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * ParallelHash test vectors from:
 * <p>
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
 */
public class ParallelHashTest
    extends SimpleTest
{
    public String getName()
    {
        return "ParallelHash";
    }

    public void performTest()
        throws Exception
    {
        ParallelHash  pHash = new ParallelHash(128, new byte[0], 8);

        byte[] data = Hex.decode("00 01 02 03 04 05 06 07 10 11 12 13 14 15 16 17 20 21 22 23 24 25 26 27");
        pHash.update(data, 0, data.length);

        byte[] res = new byte[pHash.getDigestSize()];

        pHash.doFinal(res, 0);

        isTrue("oops!", Arrays.areEqual(Hex.decode("BA 8D C1 D1 D9 79 33 1D 3F 81 36 03 C6 7F 72 609A B5 E4 4B 94 A0 B8 F9 AF 46 51 44 54 A2 B4 F5"), res));

        pHash = new ParallelHash(128, Strings.toByteArray("Parallel Data"), 8);

        pHash.update(data, 0, data.length);

        res = new byte[pHash.getDigestSize()];

        pHash.doFinal(res, 0);

        isTrue("oops!", Arrays.areEqual(Hex.decode("FC 48 4D CB 3F 84 DC EE DC 35 34 38 15 1B EE 58 15 7D 6E FE D0 44 5A 81 F1 65 E4 95 79 5B 72 06"), res));

        pHash = new ParallelHash(128, Strings.toByteArray("Parallel Data"), 12);

        data = Hex.decode("00 01 02 03 04 05 06 07 08 09 0A 0B 10 11 12 13 14 15 16 17 18 19 1A 1B 20 21 22 23 24 25 26 27 28 29 2A 2B 30 31 32 33 34 35 36 37 38 39 3A 3B 40 41 42 43 44 45 46 47 48 49 4A 4B 50 51 52 53 54 55 56 57 58 59 5A 5B");

        pHash.update(data, 0, data.length);

        res = new byte[pHash.getDigestSize()];

        pHash.doFinal(res, 0);

        isTrue("oops!", Arrays.areEqual(Hex.decode("F7 FD 53 12 89 6C 66 85 C8 28 AF 7E 2A DB 97 E3 93 E7 F8 D5 4E 3C 2E A4 B9 5E 5A CA 37 96 E8 FC"), res));

        pHash = new ParallelHash(256, new byte[0], 8);

        data = Hex.decode("00 01 02 03 04 05 06 07 10 11 12 13 14 15 16 17 20 21 22 23 24 25 26 27");

        pHash.update(data, 0, data.length);

        res = new byte[pHash.getDigestSize()];

        pHash.doFinal(res, 0);

        isTrue("oops!", Arrays.areEqual(Hex.decode("BC 1E F1 24 DA 34 49 5E 94 8E AD 20 7D D9 84 22 35 DA 43 2D 2B BC 54 B4 C1 10 E6 4C 45 11 05 53 1B 7F 2A 3E 0C E0 55 C0 28 05 E7 C2 DE 1F B7 46 AF 97 A1 DD 01 F4 3B 82 4E 31 B8 76 12 41 04 29"), res));

        pHash = new ParallelHash(256, Strings.toByteArray("Parallel Data"), 8);

        data = Hex.decode("00 01 02 03 04 05 06 07 10 11 12 13 14 15 16 17 20 21 22 23 24 25 26 27");

        pHash.update(data, 0, data.length);

        res = new byte[pHash.getDigestSize()];

        pHash.doFinal(res, 0);

        isTrue("oops!", Arrays.areEqual(Hex.decode("CD F1 52 89 B5 4F 62 12 B4 BC 27 05 28 B4 95 26 00 6D D9 B5 4E 2B 6A DD 1E F6 90 0D DA 39 63 BB 33 A7 24 91 F2 36 96 9C A8 AF AE A2 9C 68 2D 47 A3 93 C0 65 B3 8E 29 FA E6 51 A2 09 1C 83 31 10"), res));

        pHash = new ParallelHash(256, Strings.toByteArray("Parallel Data"), 12);

        data = Hex.decode("00 01 02 03 04 05 06 07 08 09 0A 0B 10 11 12 13 14 15 16 17 18 19 1A 1B 20 21 22 23 24 25 26 27 28 29 2A 2B 30 31 32 33 34 35 36 37 38 39 3A 3B 40 41 42 43 44 45 46 47 48 49 4A 4B 50 51 52 53 54 55 56 57 58 59 5A 5B");

        pHash.update(data, 0, data.length);

        res = new byte[pHash.getDigestSize()];

        pHash.doFinal(res, 0);

        isTrue("oops!", Arrays.areEqual(Hex.decode("69 D0 FC B7 64 EA 05 5D D0 93 34 BC 60 21 CB 7E 4B 61 34 8D FF 37 5D A2 62 67 1C DE C3 EF FA 8D 1B 45 68 A6 CC E1 6B 1C AD 94 6D DD E2 7F 6C E2 B8 DE E4 CD 1B 24 85 1E BF 00 EB 90 D4 38 13 E9"), res));

        pHash = new ParallelHash(128, Strings.toByteArray("Parallel Data"), 12);

        data = Hex.decode("00 01 02 03 04 05 06 07 08 09 0A 0B 10 11 12 13 14 15 16 17 18 19 1A 1B 20 21 22 23 24 25 26 27 28 29 2A 2B 30 31 32 33 34 35 36 37 38 39 3A 3B 40 41 42 43 44 45 46 47 48 49 4A 4B 50 51 52 53 54 55 56 57 58 59 5A 5B");
        pHash.update(data, 0, data.length);

        res = new byte[32];

        pHash.doOutput(res, 0, res.length);

        isTrue("oops!", !Arrays.areEqual(Hex.decode("F7 FD 53 12 89 6C 66 85 C8 28 AF 7E 2A DB 97 E3 93 E7 F8 D5 4E 3C 2E A4 B9 5E 5A CA 37 96 E8 FC"), res));
        isTrue("oops!", Arrays.areEqual(Hex.decode("0127ad9772ab904691987fcc4a24888f341fa0db2145e872d4efd255376602f0"), res));

        pHash = new ParallelHash(256, Strings.toByteArray("Parallel Data"), 12);

        data = Hex.decode("00 01 02 03 04 05 06 07 08 09 0A 0B 10 11 12 13 14 15 16 17 18 19 1A 1B 20 21 22 23 24 25 26 27 28 29 2A 2B 30 31 32 33 34 35 36 37 38 39 3A 3B 40 41 42 43 44 45 46 47 48 49 4A 4B 50 51 52 53 54 55 56 57 58 59 5A 5B");
        pHash.update(data, 0, data.length);

        res = new byte[64];

        pHash.doOutput(res, 0, res.length);

        isTrue("oops!", !Arrays.areEqual(Hex.decode("69 D0 FC B7 64 EA 05 5D D0 93 34 BC 60 21 CB 7E 4B 61 34 8D FF 37 5D A2 62 67 1C DE C3 EF FA 8D 1B 45 68 A6 CC E1 6B 1C AD 94 6D DD E2 7F 6C E2 B8 DE E4 CD 1B 24 85 1E BF 00 EB 90 D4 38 13 E9"), res));
        isTrue("oops!", Arrays.areEqual(Hex.decode("6b3e790b330c889a204c2fbc728d809f19367328d852f4002dc829f73afd6bcefb7fe5b607b13a801c0be5c1170bdb794e339458fdb0e62a6af3d42558970249"), res));

        testEmpty();
    }

    private void testEmpty()
    {
        //{"tcId":90,"msg":"","len":0,"blockSize":62,"customization":"Ny0LL2tUmt\u003C\u002BkuN5:Z7pZ_7]R; l/i:%pWbo4}","outLen":16},
        //{"tcId":90,"md":"13C4","outLen":16}
        ParallelHash pHash = new ParallelHash(256, Strings.toByteArray("Ny0LL2tUmt\u003C\u002BkuN5:Z7pZ_7]R; l/i:%pWbo4}"), 62);

        pHash.update(new byte[0], 0, 0);

        byte[] res = new byte[16 / 8];

        pHash.doOutput(res, 0, res.length);

        isTrue(Arrays.areEqual(Hex.decode("13C4"), res));
    }

     public static void main(
         String[]    args)
     {
         runTest(new ParallelHashTest());
     }
}
