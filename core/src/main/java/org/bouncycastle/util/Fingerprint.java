package org.bouncycastle.util;

import org.bouncycastle.crypto.digests.SHA512tDigest;

public class Fingerprint
{
    private static char[] encodingTable =
    {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private final byte[] fingerprint;

    public Fingerprint(byte[] source)
    {
        this.fingerprint = calculateFingerprint(source);
    }

    public byte[] getFingerprint()
    {
        return Arrays.clone(fingerprint);
    }

    public String toString()
    {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i != fingerprint.length; i++)
        {
            if (i > 0)
            {
                sb.append(":");
            }
            sb.append(encodingTable[(fingerprint[i] >>> 4) & 0xf]);
            sb.append(encodingTable[fingerprint[i] & 0x0f]);
        }

        return sb.toString();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof Fingerprint)
        {
            return Arrays.areEqual(((Fingerprint)o).fingerprint, fingerprint);
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(fingerprint);
    }

    public static byte[] calculateFingerprint(byte[] input)
    {
        SHA512tDigest digest = new SHA512tDigest(160);

        digest.update(input, 0, input.length);

        byte[] rv = new byte[digest.getDigestSize()];

        digest.doFinal(rv, 0);

        return rv;
    }
}
