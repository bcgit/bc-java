package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.pqc.math.ntru.HPSPolynomial;
import org.bouncycastle.pqc.math.ntru.HRSSPolynomial;
import org.bouncycastle.pqc.math.ntru.Polynomial;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.util.Arrays;

/**
 * NTRU sampling.
 *
 * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.10
 */
class NTRUSampling
{
    private final NTRUParameterSet params;

    /**
     * Constructor
     *
     * @param params an NTRU parameter set
     */
    public NTRUSampling(NTRUParameterSet params)
    {
        this.params = params;
    }

    /**
     * @param uniformBytes random byte array
     * @return a pair of polynomial {@code f} and {@code g}
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.10.1
     */
    public PolynomialPair sampleFg(byte[] uniformBytes)
    {
        // assert uniformBytes.length == this.params.sampleFgBytes();
        if (this.params instanceof NTRUHRSSParameterSet)
        {
            HRSSPolynomial f = this.sampleIidPlus(Arrays.copyOfRange(uniformBytes, 0, this.params.sampleIidBytes()));
            // len(uniformBytes) = sampleIidBytes * 2
            HRSSPolynomial g = this.sampleIidPlus(Arrays.copyOfRange(uniformBytes, this.params.sampleIidBytes(), uniformBytes.length));
            return new PolynomialPair(f, g);
        }
        else if (this.params instanceof NTRUHPSParameterSet)
        {
            HPSPolynomial f = (HPSPolynomial)this.sampleIid(Arrays.copyOfRange(uniformBytes, 0, this.params.sampleIidBytes()));
            // len(uniformBytes) = sampleIidBytes + sampleFixedTypeBytes
            HPSPolynomial g = this.sampleFixedType(Arrays.copyOfRange(uniformBytes, this.params.sampleIidBytes(), uniformBytes.length));
            return new PolynomialPair(f, g);
        }
        else
        {
            throw new IllegalArgumentException("Invalid polynomial type");
        }
    }

    /**
     * @param uniformBytes random byte array
     * @return a pair of polynomial {@code r} and {@code m}
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.10.2
     */
    public PolynomialPair sampleRm(byte[] uniformBytes)
    {
        // assert uniformBytes.length == this.params.sampleRmBytes();
        if (this.params instanceof NTRUHRSSParameterSet)
        {
            HRSSPolynomial r = (HRSSPolynomial)this.sampleIid(Arrays.copyOfRange(uniformBytes, 0, this.params.sampleIidBytes()));
            HRSSPolynomial m = (HRSSPolynomial)this.sampleIid(Arrays.copyOfRange(uniformBytes, this.params.sampleIidBytes(), uniformBytes.length));
            return new PolynomialPair(r, m);
        }
        else if (this.params instanceof NTRUHPSParameterSet)
        {
            HPSPolynomial r = (HPSPolynomial)this.sampleIid(Arrays.copyOfRange(uniformBytes, 0, this.params.sampleIidBytes()));
            HPSPolynomial m = this.sampleFixedType(Arrays.copyOfRange(uniformBytes, this.params.sampleIidBytes(), uniformBytes.length));
            return new PolynomialPair(r, m);
        }
        else
        {
            throw new IllegalArgumentException("Invalid polynomial type");
        }
    }

    /**
     * @param uniformBytes random byte array
     * @return a ternary polynomial
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.10.3
     */
    public Polynomial sampleIid(byte[] uniformBytes)
    {
        // assert uniformBytes.length == this.params.sampleIidBytes();
        Polynomial r = this.params.createPolynomial();
        for (int i = 0; i < this.params.n() - 1; i++)
        {
            r.coeffs[i] = (short)mod3(uniformBytes[i] & 0xff);
        }
        r.coeffs[this.params.n() - 1] = 0;
        return r;
    }

    /**
     * @param uniformBytes random byte array
     * @return a ternary polynomial with exactly q/16 − 1 coefficients equal to 1 and q/16 − 1 coefficient equal to −1
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.10.5
     */
    public HPSPolynomial sampleFixedType(byte[] uniformBytes)
    {
        // assert uniformBytes.length == this.params.sampleFixedTypeBytes();
        int n = this.params.n();
        int weight = ((NTRUHPSParameterSet)this.params).weight();
        HPSPolynomial r = new HPSPolynomial((NTRUHPSParameterSet)this.params);
        int[] s = new int[n - 1];
        int i;

        for (i = 0; i < (n - 1) / 4; i++)
        {
            s[4 * i + 0] = ((uniformBytes[15 * i + 0] & 0xff) << 2) + ((uniformBytes[15 * i + 1] & 0xff) << 10) + ((uniformBytes[15 * i + 2] & 0xff) << 18) + ((uniformBytes[15 * i + 3] & 0xff) << 26);
            s[4 * i + 1] = (((uniformBytes[15 + i * 3] & 0xff) & 0xc0) >> 4) + ((uniformBytes[15 * i + 4] & 0xff) << 4) + ((uniformBytes[15 * i + 5] & 0xff) << 12) + ((uniformBytes[15 * i + 6] & 0xff) << 20) + ((uniformBytes[15 * i + 7] & 0xff) << 28);
            s[4 * i + 2] = (((uniformBytes[15 + i * 7] & 0xff) & 0xf0) >> 2) + ((uniformBytes[15 * i + 8] & 0xff) << 6) + ((uniformBytes[15 * i + 9] & 0xff) << 14) + ((uniformBytes[15 * i + 10] & 0xff) << 22) + ((uniformBytes[15 * i + 11] & 0xff) << 30);
            s[4 * i + 3] = ((uniformBytes[15 * i + 11] & 0xff) & 0xfc) + ((uniformBytes[15 * i + 12] & 0xff) << 8) + ((uniformBytes[15 * i + 13] & 0xff) << 16) + ((uniformBytes[15 * i + 14] & 0xff) << 24);
        }

        // (N-1) = 2 mod 4
        if (n - 1 > ((n - 1) / 4) * 4)
        {
            i = (n - 1) / 4;
            s[4 * i + 0] = ((uniformBytes[15 * i + 0] & 0xff) << 2) + ((uniformBytes[15 * i + 1] & 0xff) << 10) + ((uniformBytes[15 * i + 2] & 0xff) << 18) + ((uniformBytes[15 * i + 3] & 0xff) << 26);
            s[4 * i + 1] = (((uniformBytes[15 + i * 3] & 0xff) & 0xc0) >> 4) + ((uniformBytes[15 * i + 4] & 0xff) << 4) + ((uniformBytes[15 * i + 5] & 0xff) << 12) + ((uniformBytes[15 * i + 6] & 0xff) << 20) + ((uniformBytes[15 * i + 7] & 0xff) << 28);
        }

        for (i = 0; i < weight / 2; i++)
        {
            s[i] |= 1;
        }

        for (i = weight / 2; i < weight; i++)
        {
            s[i] |= 2;
        }

        java.util.Arrays.sort(s);

        for (i = 0; i < n - 1; i++)
        {
            r.coeffs[i] = (short)(s[i] & 3);
        }

        r.coeffs[n - 1] = 0;
        return r;
    }

    /**
     * @param uniformBytes random byte array
     * @return a ternary polynomial that satisfies the non-negative correlation property
     * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a> section 1.10.4
     */
    public HRSSPolynomial sampleIidPlus(byte[] uniformBytes)
    {
        // assert uniformBytes.length == this.params.sampleIidBytes();
        int n = this.params.n();
        int i;
        short s = 0;
        HRSSPolynomial r = (HRSSPolynomial)sampleIid(uniformBytes);

        /* Map {0,1,2} -> {0, 1, 2^16 - 1} */
        for (i = 0; i < n - 1; i++)
        {
            r.coeffs[i] = (short)(r.coeffs[i] | (-(r.coeffs[i] >>> 1)));
        }

        /* s = <x*r, r>.  (r[n-1] = 0) */
        for (i = 0; i < n - 1; i++)
        {
            s += (short)(r.coeffs[i + 1] * r.coeffs[i]);
        }

        /* Extract sign of s (sign(0) = 1) */
        s = (short)(1 | (-((s & 0xffff) >>> 15)));

        for (i = 0; i < n - 1; i += 2)
        {
            r.coeffs[i] = (short)(s * r.coeffs[i]);
        }

        /* Map {0,1,2^16-1} -> {0, 1, 2} */
        for (i = 0; i < n - 1; i++)
        {
            r.coeffs[i] = (short)(3 & ((r.coeffs[i] & 0xffff) ^ ((r.coeffs[i] & 0xffff) >>> 15)));
        }

        return r;
    }

    private static int mod3(int a)
    {
        return a % 3;
    }
}
