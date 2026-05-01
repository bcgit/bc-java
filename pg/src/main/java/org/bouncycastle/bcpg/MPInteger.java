package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.BigIntegers;

/**
 * a multiple precision integer
 */
public class MPInteger 
    extends BCPGObject
{
    private final BigInteger value;

    public MPInteger(BCPGInputStream in) throws IOException
    {
        /*
         * TODO RFC 9580 3.2. When parsing an MPI in a version 6 Key, Signature, or Public Key Encrypted
         * Session Key (PKESK) packet, the implementation MUST check that the encoded length matches the
         * length starting from the most significant non-zero bit; if it doesn't match, reject the packet as
         * malformed.
         */
        boolean validateLength = false;

        this.value = readMPI(in, validateLength);
    }

    public MPInteger(BigInteger value)
    {
        if (value == null || value.signum() < 0)
        {
            throw new IllegalArgumentException("value must not be null, or negative");
        }

        this.value = value;
    }

    public BigInteger getValue()
    {
        return value;
    }

    public void encode(BCPGOutputStream out) throws IOException
    {
        StreamUtil.write2OctetLength(out, value.bitLength());
        BigIntegers.writeUnsignedByteArray(out, value);
    }

    private static BigInteger readMPI(BCPGInputStream in, boolean validateLength) throws IOException
    {
        int bitLength = StreamUtil.read2OctetLength(in);
        int byteLength = (bitLength + 7) / 8;
        byte[] bytes = new byte[byteLength];
        in.readFully(bytes);
        BigInteger n = new BigInteger(1, bytes);

        if (validateLength && n.bitLength() != bitLength)
        {
            throw new IOException("malformed MPI");
        }

        return n;
    }
}
