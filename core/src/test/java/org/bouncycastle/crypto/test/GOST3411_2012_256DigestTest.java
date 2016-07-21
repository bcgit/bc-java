package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;

import java.util.ArrayList;

public class GOST3411_2012_256DigestTest
    extends DigestTest
{
    private static final String[] messages;
    static {
        ArrayList<String> strList = new ArrayList<String>();
        strList.add("012345678901234567890123456789012345678901234567890123456789012");

        char[] M2 = {0xD1, 0xE5, 0x20, 0xE2, 0xE5, 0xF2, 0xF0, 0xE8, 0x2C, 0x20, 0xD1, 0xF2,
                     0xF0, 0xE8, 0xE1, 0xEE, 0xE6, 0xE8, 0x20, 0xE2, 0xED, 0xF3, 0xF6, 0xE8,
                     0x2C, 0x20, 0xE2, 0xE5, 0xFE, 0xF2, 0xFA, 0x20, 0xF1, 0x20, 0xEC, 0xEE,
                     0xF0, 0xFF, 0x20, 0xF1, 0xF2, 0xF0, 0xE5, 0xEB, 0xE0, 0xEC, 0xE8, 0x20,
                     0xED, 0xE0, 0x20, 0xF5, 0xF0, 0xE0, 0xE1, 0xF0, 0xFB, 0xFF, 0x20, 0xEF,
                     0xEB, 0xFA, 0xEA, 0xFB, 0x20, 0xC8, 0xE3, 0xEE, 0xF0, 0xE5, 0xE2, 0xFB};
        strList.add(new String(M2));

        messages = new String[strList.size()];
        for (int i = 0; i < strList.size(); i++) {
            messages[i] = strList.get(i);
        }
    };

    private static final String[] digests = {
        "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d",
        "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d"
    };

    GOST3411_2012_256DigestTest() {
        super(new GOST3411_2012_256Digest(), messages, digests);
    }

    @Override
    protected Digest cloneDigest(Digest digest) {
        return new GOST3411_2012_256Digest((GOST3411_2012_256Digest)digest);
    }

    public static void main(String[] args) {
        runTest(new GOST3411_2012_256DigestTest());
    }
}
