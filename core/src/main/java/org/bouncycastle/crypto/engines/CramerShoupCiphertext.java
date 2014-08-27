package org.bouncycastle.crypto.engines;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Class, holding Cramer Shoup ciphertexts (u1, u2, e, v)
 */
public class CramerShoupCiphertext
{
    BigInteger u1, u2, e, v;

    public CramerShoupCiphertext()
    {
    }

    public CramerShoupCiphertext(BigInteger u1, BigInteger u2, BigInteger e, BigInteger v)
    {
        this.u1 = u1;
        this.u2 = u2;
        this.e = e;
        this.v = v;
    }

    public CramerShoupCiphertext(byte[] c)
    {
        int off = 0, s;
        byte[] tmp;

        s = Pack.bigEndianToInt(c, off);
        off += 4;
        tmp = Arrays.copyOfRange(c, off, off + s);
        off += s;
        u1 = new BigInteger(tmp);

        s = Pack.bigEndianToInt(c, off);
        off += 4;
        tmp = Arrays.copyOfRange(c, off, off + s);
        off += s;
        u2 = new BigInteger(tmp);

        s = Pack.bigEndianToInt(c, off);
        off += 4;
        tmp = Arrays.copyOfRange(c, off, off + s);
        off += s;
        e = new BigInteger(tmp);

        s = Pack.bigEndianToInt(c, off);
        off += 4;
        tmp = Arrays.copyOfRange(c, off, off + s);
        off += s;
        v = new BigInteger(tmp);
    }

    public BigInteger getU1()
    {
        return u1;
    }

    public void setU1(BigInteger u1)
    {
        this.u1 = u1;
    }

    public BigInteger getU2()
    {
        return u2;
    }

    public void setU2(BigInteger u2)
    {
        this.u2 = u2;
    }

    public BigInteger getE()
    {
        return e;
    }

    public void setE(BigInteger e)
    {
        this.e = e;
    }

    public BigInteger getV()
    {
        return v;
    }

    public void setV(BigInteger v)
    {
        this.v = v;
    }

    public String toString()
    {
        StringBuffer result = new StringBuffer();

        result.append("u1: " + u1.toString());
        result.append("\nu2: " + u2.toString());
        result.append("\ne: " + e.toString());
        result.append("\nv: " + v.toString());

        return result.toString();
    }

    /**
     * convert the cipher-text in a byte array,
     * prepending them with 4 Bytes for their length
     *
     * @return
     */
    public byte[] toByteArray()
    {
        byte[] u1Bytes = u1.toByteArray();
        int u1Length = u1Bytes.length;
        byte[] u2Bytes = u2.toByteArray();
        int u2Length = u2Bytes.length;
        byte[] eBytes = e.toByteArray();
        int eLength = eBytes.length;
        byte[] vBytes = v.toByteArray();
        int vLength = vBytes.length;

        int off = 0;
        byte[] result = new byte[u1Length + u2Length + eLength + vLength + 4 * 4];
        Pack.intToBigEndian(u1Length, result, off);
        off += 4;
        System.arraycopy(u1Bytes, 0, result, off, u1Length);
        off += u1Length;
        Pack.intToBigEndian(u2Length, result, off);
        off += 4;
        System.arraycopy(u2Bytes, 0, result, off, u2Length);
        off += u2Length;
        Pack.intToBigEndian(eLength, result, off);
        off += 4;
        System.arraycopy(eBytes, 0, result, off, eLength);
        off += eLength;
        Pack.intToBigEndian(vLength, result, off);
        off += 4;
        System.arraycopy(vBytes, 0, result, off, vLength);
        off += vLength;

        return result;
    }
}