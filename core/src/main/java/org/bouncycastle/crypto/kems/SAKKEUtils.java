package org.bouncycastle.crypto.kems;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class SAKKEUtils
{
    public static BigInteger hashToIntegerRange(byte[] input, BigInteger q)
    {
        // RFC 6508 Section 5.1: Hashing to an Integer Range
        SHA256Digest digest = new SHA256Digest();
        byte[] hash = new byte[digest.getDigestSize()];

        // Step 1: Compute A = hashfn(s)
        digest.update(input, 0, input.length);
        digest.doFinal(hash, 0);
        byte[] A = hash.clone();

        // Step 2: Initialize h_0 to all-zero bytes of hashlen size
        byte[] h = new byte[digest.getDigestSize()];

        // Step 3: Compute l = Ceiling(lg(n)/hashlen)
        int l = q.bitLength() >> 8;

        BigInteger v = BigInteger.ZERO;

        // Step 4: Compute h_i and v_i
        for (int i = 1; i <= l; i++)
        {
            // h_i = hashfn(h_{i-1})
            digest.update(h, 0, h.length);
            digest.doFinal(h, 0);
            System.out.println("h_"+i+":" +new String(Hex.encode(h)));
            // v_i = hashfn(h_i || A)
            digest.update(h, 0, h.length);
            digest.update(A, 0, A.length);
            byte[] v_i = new byte[digest.getDigestSize()];
            digest.doFinal(v_i, 0);
            System.out.println("v_"+i+":" +new String(Hex.encode(v_i)));
            // Append v_i to v'
            v = v.shiftLeft(v_i.length * 8).add(new BigInteger(1, v_i));
        }
        System.out.println("v:" +new String(Hex.encode(v.toByteArray())));
        // Step 6: v = v' mod n
        return v.mod(q);
    }

    public static byte[] hash(byte[] data)
    {
        Digest digest = new SHA256Digest();
        byte[] rlt = new byte[digest.getDigestSize()];
        digest.update(data, 0, data.length);
        digest.doFinal(rlt, 0);
        return rlt;
    }

    public static byte[] hash(ECPoint point)
    {
        return hash(point.getEncoded(false)); // Use uncompressed encoding
    }
}
