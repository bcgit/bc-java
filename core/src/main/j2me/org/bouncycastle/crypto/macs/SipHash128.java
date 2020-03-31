package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.util.Pack;

/**
 * Implementation of SipHash with 128 bit output.
 * <p>
 * Based on the {@link SipHash} and the C reference implementation
 * https://github.com/veorq/SipHash.
 * 
 */
public class SipHash128
    extends SipHash
{

    /**
     * SipHash128-2-4
     */
    public SipHash128()
    {
      super();
    }

    /**
     * SipHash128-c-d
     *
     * @param c the number of compression rounds
     * @param d the number of finalization rounds
     */
    public SipHash128(int c, int d)
    {
       super(c, d);
    }

    public String getAlgorithmName()
    {
        return "SipHash128-" + c + "-" + d;
    }

    public int getMacSize()
    {
        return 16;
    }

    public long doFinal()
        throws DataLengthException, IllegalStateException {
        throw new IllegalStateException("doFinal() is not supported");
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        // NOTE: 2 distinct shifts to avoid "64-bit shift" when wordPos == 0
        m >>>= ((7 - wordPos) << 3);
        m >>>= 8;
        m |= (((wordCount << 3) + wordPos) & 0xffL) << 56;

        processMessageWord();

        v2 ^= 0xeeL;

        applySipRounds(d);

        long r0 = v0 ^ v1 ^ v2 ^ v3;

        v1 ^= 0xddL;
        applySipRounds(d);

        long r1 = v0 ^ v1 ^ v2 ^ v3;

        reset();

        Pack.longToLittleEndian(r0, out, outOff);
        Pack.longToLittleEndian(r1, out, outOff + 8);
        return 16;
    }

    public void reset()
    {
        super.reset();
        v1 ^= 0xeeL;
    }

}
