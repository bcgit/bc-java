package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * implementation of SHA-3 based on following KeccakNISTInterface.c from https://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class SHA3Digest
    extends KeccakDigest
    implements SavableDigest
{
    private static int checkBitLength(int bitLength)
    {
        switch (bitLength)
        {
        case 224:
        case 256:
        case 384:
        case 512:
            return bitLength;
        default:
            throw new IllegalArgumentException("'bitLength' " + bitLength + " not supported for SHA-3");
        }
    }

    public SHA3Digest()
    {
        this(256, CryptoServicePurpose.ANY);
    }

    public SHA3Digest(CryptoServicePurpose purpose)
    {
        this(256, purpose);
    }

    public SHA3Digest(int bitLength)
    {
        super(checkBitLength(bitLength), CryptoServicePurpose.ANY);
    }

    public SHA3Digest(int bitLength, CryptoServicePurpose purpose)
    {
        super(checkBitLength(bitLength), purpose);
    }

    public SHA3Digest(byte[] encodedState)
    {
        super(getCryptoServicePurpose(encodedState[encodedState.length - 1]));

        Pack.bigEndianToLong(encodedState, 0, state, 0, state.length);
        int encOff = state.length * 8;
        System.arraycopy(encodedState, encOff, dataQueue, 0, dataQueue.length);
        encOff += dataQueue.length;
        rate = Pack.bigEndianToInt(encodedState, encOff);
        encOff += 4;
        bitsInQueue = Pack.bigEndianToInt(encodedState, encOff);
        encOff += 4;
        fixedOutputLength = Pack.bigEndianToInt(encodedState, encOff);
        encOff += 4;
        squeezing = encodedState[encOff] != 0;
    }

    private static CryptoServicePurpose getCryptoServicePurpose(byte b)
    {
        CryptoServicePurpose[] values = CryptoServicePurpose.values();
        return values[b];
    }

    public SHA3Digest(SHA3Digest source)
    {
        super(source);
    }

    private void copyIn(SHA3Digest source)
    {
        if (this.purpose != source.purpose)
        {
            throw new IllegalArgumentException("attempt to copy digest of different purpose");
        }

        System.arraycopy(source.state, 0, this.state, 0, source.state.length);
        System.arraycopy(source.dataQueue, 0, this.dataQueue, 0, source.dataQueue.length);
        this.rate = source.rate;
        this.bitsInQueue = source.bitsInQueue;
        this.fixedOutputLength = source.fixedOutputLength;
        this.squeezing = source.squeezing;

        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    public String getAlgorithmName()
    {
        return "SHA3-" + fixedOutputLength;
    }

    public int doFinal(byte[] out, int outOff)
    {
        absorbBits(0x02, 2);
        
        return super.doFinal(out,  outOff);
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    protected int doFinal(byte[] out, int outOff, byte partialByte, int partialBits)
    {
        if (partialBits < 0 || partialBits > 7)
        {
            throw new IllegalArgumentException("'partialBits' must be in the range [0,7]");
        }

        int finalInput = (partialByte & ((1 << partialBits) - 1)) | (0x02 << partialBits);
        int finalBits = partialBits + 2;

        if (finalBits >= 8)
        {
            absorb((byte)finalInput);
            finalBits -= 8;
            finalInput >>>= 8;
        }

        return super.doFinal(out, outOff, (byte)finalInput, finalBits);
    }

    public byte[] getEncodedState()
    {
        byte[] encState = new byte[state.length * 8 + dataQueue.length + 12 + 2];

        for (int i = 0; i != state.length; i++)
        {
            Pack.longToBigEndian(state[i], encState, i * 8);
        }

        int sOff = state.length * 8;
        System.arraycopy(dataQueue, 0, encState, sOff, dataQueue.length);

        sOff += dataQueue.length;
        Pack.intToBigEndian(rate, encState, sOff);
        sOff += 4;
        Pack.intToBigEndian(bitsInQueue, encState, sOff);
        sOff += 4;
        Pack.intToBigEndian(fixedOutputLength, encState, sOff);
        sOff += 4;
        encState[sOff++] = squeezing ? (byte)1 : (byte)0;
        encState[sOff] = (byte)purpose.ordinal();

        return encState;
    }

    public Memoable copy()
    {
        return new SHA3Digest(this);
    }

    public void reset(Memoable other)
    {
        SHA3Digest d = (SHA3Digest)other;

        copyIn(d);
    }
}
