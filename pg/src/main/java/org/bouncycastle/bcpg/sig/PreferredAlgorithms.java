package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;

/**
 * Signature Subpacket containing algorithm preferences of the key holder's implementation.
 * This class is used to implement:
 * <ul>
 *     <li>Preferred Hash Algorithms</li>
 *     <li>Preferred Symmetric Key Algorithms</li>
 *     <li>Preferred Compression Algorithms</li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-symmetric-ciphers">
 *     RFC9580 - Preferred Symmetric Ciphers for v1 SEIPD</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-hash-algorithms">
 *     RFC9580 - Preferred Hash Algorithms</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-compression-algor">
 *     RFC9580 - Preferred Compression Algorithms</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.7">
 *     RFC4880 - Preferred Symmetric Algorithms</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.8">
 *     RFC4880 - Preferred Hash Algorithms</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.9">
 *     RFC4880 - Preferred Compression Algorithms</a>
 */
public class PreferredAlgorithms 
    extends SignatureSubpacket
{    
    protected static byte[] intToByteArray(
        int[]    v)
    {
        byte[]    data = new byte[v.length];
        
        for (int i = 0; i != v.length; i++)
        {
            data[i] = (byte)v[i];
        }
        
        return data;
    }
    
    public PreferredAlgorithms(
        int        type,
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(type, critical, isLongLength, data);
    }
    
    public PreferredAlgorithms(
        int        type,
        boolean    critical,
        int[]      preferences)
    {
        super(type, critical, false, intToByteArray(preferences));
    }

    public int[] getPreferences()
    {
        int[]    v = new int[data.length];
        
        for (int i = 0; i != v.length; i++)
        {
            v[i] = data[i] & 0xff;
        }
        
        return v;
    }
}
