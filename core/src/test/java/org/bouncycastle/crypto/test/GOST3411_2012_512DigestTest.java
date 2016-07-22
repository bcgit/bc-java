package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;

import java.util.ArrayList;

public class GOST3411_2012_512DigestTest
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
            "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00" +
                    "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b",
            "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03" +
                    "7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e"
    };

    public GOST3411_2012_512DigestTest() {
        super(new GOST3411_2012_512Digest(), messages, digests);
    }

    @Override
    protected Digest cloneDigest(Digest digest) {
        return new GOST3411_2012_512Digest((GOST3411_2012_512Digest)digest);
    }

    public static void main(String[] args) {
        runTest(new GOST3411_2012_512DigestTest());
    }
}
