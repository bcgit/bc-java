package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * A deterministic K calculator based on the algorithm in section 3.2 of RFC 6979.
 */
public class HMacDSAKCalculator
    implements DSAKCalculator
{
    private final HMac hMac;
    private final byte[] K;
    private final byte[] V;

    private BigInteger n;

    /**
     * Base constructor.
     *
     * @param digest digest to build the HMAC on.
     */
    public HMacDSAKCalculator(Digest digest)
    {
        this.hMac = new HMac(digest);

        int macSize = hMac.getMacSize();
        this.V = new byte[macSize];
        this.K = new byte[macSize];
    }

    public boolean isDeterministic()
    {
        return true;
    }

    public void init(BigInteger n, SecureRandom random)
    {
        throw new IllegalStateException("Operation not supported");
    }

    public void init(BigInteger n, BigInteger d, byte[] message)
    {
        this.n = n;

        BigInteger mInt = bitsToInt(message);
        if (mInt.compareTo(n) >= 0)
        {
            mInt = mInt.subtract(n);
        }

        int size = BigIntegers.getUnsignedByteLength(n);

        byte[] x = BigIntegers.asUnsignedByteArray(size, d);
        byte[] m = BigIntegers.asUnsignedByteArray(size, mInt);

        Arrays.fill(K, (byte)0x00);
        Arrays.fill(V, (byte)0x01);

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);
        hMac.update((byte)0x00);
        hMac.update(x, 0, x.length);
        hMac.update(m, 0, m.length);
        initAdditionalInput0(hMac);
        hMac.doFinal(K, 0);

        hMac.init(new KeyParameter(K));
        hMac.update(V, 0, V.length);
        hMac.doFinal(V, 0);

        hMac.update(V, 0, V.length);
        hMac.update((byte)0x01);
        hMac.update(x, 0, x.length);
        hMac.update(m, 0, m.length);
        initAdditionalInput1(hMac);
        hMac.doFinal(K, 0);

        hMac.init(new KeyParameter(K));
        hMac.update(V, 0, V.length);
        hMac.doFinal(V, 0);
    }

    public BigInteger nextK()
    {
        byte[] t = new byte[BigIntegers.getUnsignedByteLength(n)];

        for (;;)
        {
            int tOff = 0;

            while (tOff < t.length)
            {
                hMac.update(V, 0, V.length);
                hMac.doFinal(V, 0);

                int len = Math.min(t.length - tOff, V.length);
                System.arraycopy(V, 0, t, tOff, len);
                tOff += len;
            }

            BigInteger k = bitsToInt(t);

            if (k.signum() > 0 && k.compareTo(n) < 0)
            {
                return k;
            }

            hMac.update(V, 0, V.length);
            hMac.update((byte)0x00);
            hMac.doFinal(K, 0);

            hMac.init(new KeyParameter(K));
            hMac.update(V, 0, V.length);
            hMac.doFinal(V, 0);
        }
    }

    /**
     * Supply additional input to HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1)).
     * <p/>
     * RFC 6979 3.6. Additional data may be added to the input of HMAC [..]. A use case may be a protocol that
     * requires a non-deterministic signature algorithm on a system that does not have access to a
     * high-quality random source. It suffices that the additional data [..] is non-repeating (e.g., a
     * signature counter or a monotonic clock) to ensure "random-looking" signatures are indistinguishable, in
     * a cryptographic way, from plain (EC)DSA signatures.
     * <p/>
     * By default there is no additional input. Override this method to supply additional input, bearing in
     * mind that this calculator may be used for many signatures.
     *
     * @param hmac0 the {@link HMac} to which the additional input should be added.
     */
    protected void initAdditionalInput0(HMac hmac0)
    {
    }

    /**
     * Supply additional input to HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)).
     * <p/>
     * Refer to comments for {@link #initAdditionalInput0(HMac)}.
     *
     * @param hmac1 the {@link HMac} to which the additional input should be added.
     */
    protected void initAdditionalInput1(HMac hmac1)
    {
    }

    private BigInteger bitsToInt(byte[] t)
    {
        int blen = t.length * 8;
        int qlen = n.bitLength();

        BigInteger v = BigIntegers.fromUnsignedByteArray(t);
        if (blen > qlen)
        {
            v = v.shiftRight(blen - qlen);
        }
        return v;
    }
}
