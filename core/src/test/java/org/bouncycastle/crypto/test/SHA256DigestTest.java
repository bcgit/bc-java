package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * standard vector test for SHA-256 from FIPS Draft 180-2.
 *
 * Note, the first two vectors are _not_ from the draft, the last three are.
 */
public class SHA256DigestTest
    extends DigestTest
{
    private static String[] messages =
    {
        "",
        "a",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    };
    
    private static String[] digests =
    {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    };
    
    // 1 million 'a'
    static private String  million_a_digest = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    SHA256DigestTest()
    {
        super(new SHA256Digest(), messages, digests);
    }

    public void performTest()
    {
        super.performTest();
        
        millionATest(million_a_digest);

        // test state encoding;

        byte[] lastV = toByteArray(messages[messages.length - 1]);
        byte[] lastDigest = Hex.decode(digests[digests.length - 1]);

        SHA256Digest digest = new SHA256Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];

        digest.update(lastV, 0, lastV.length/2);

        // copy the Digest
        SHA256Digest copy1 = new SHA256Digest(digest.getEncodedState());
        SHA256Digest copy2 = new SHA256Digest(copy1.getEncodedState());

        digest.update(lastV, lastV.length / 2, lastV.length - lastV.length / 2);

        digest.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing state vector test", digests[digests.length - 1], new String(Hex.encode(resBuf)));
        }

        copy1.update(lastV, lastV.length/2, lastV.length - lastV.length/2);
        copy1.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing state copy1 vector test", digests[digests.length - 1], new String(Hex.encode(resBuf)));
        }

        copy2.update(lastV, lastV.length / 2, lastV.length - lastV.length / 2);
        copy2.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing state copy2 vector test", digests[digests.length - 1], new String(Hex.encode(resBuf)));
        }
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new SHA256Digest((SHA256Digest)digest);
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new SHA256DigestTest());
    }
}
