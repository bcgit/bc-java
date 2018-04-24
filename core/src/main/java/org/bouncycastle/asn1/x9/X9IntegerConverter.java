package org.bouncycastle.asn1.x9;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;

/**
 * A class which converts integers to byte arrays, allowing padding and calculations
 * to be done according the the filed size of the curve or field element involved.
 */
public class X9IntegerConverter
{
    /**
     * Return the curve's field size in bytes.
     *
     * @param c the curve of interest.
     * @return the field size in bytes (rounded up).
     */
    public int getByteLength(
        ECCurve c)
    {
        return (c.getFieldSize() + 7) / 8;
    }

    /**
     * Return the field element's field size in bytes.
     *
     * @param fe the field element of interest.
     * @return the field size in bytes (rounded up).
     */
    public int getByteLength(
        ECFieldElement fe)
    {
        return (fe.getFieldSize() + 7) / 8;
    }

    /**
     * Convert an integer to a byte array, ensuring it is exactly qLength long.
     *
     * @param s the integer to be converted.
     * @param qLength the length
     * @return the resulting byte array.
     */
    public byte[] integerToBytes(
        BigInteger s,
        int        qLength)
    {
        byte[] bytes = s.toByteArray();
        
        if (qLength < bytes.length)
        {
            byte[] tmp = new byte[qLength];
        
            System.arraycopy(bytes, bytes.length - tmp.length, tmp, 0, tmp.length);
            
            return tmp;
        }
        else if (qLength > bytes.length)
        {
            byte[] tmp = new byte[qLength];
        
            System.arraycopy(bytes, 0, tmp, tmp.length - bytes.length, bytes.length);
            
            return tmp; 
        }
    
        return bytes;
    }
}
