package org.bouncycastle.bcpg;

import java.io.IOException;
import java.util.Date;

/**
 * basic packet for a PGP public key
 */
public class PublicSubkeyPacket 
    extends PublicKeyPacket
{
    PublicSubkeyPacket(
        BCPGInputStream    in)
        throws IOException
    {      
        super(in);
    }
    
    /**
     * Construct version 4 public subkey packet.
     * 
     * @param algorithm public key algorithm
     * @param time creation time
     * @param key key
     */
    public PublicSubkeyPacket(
        int       algorithm,
        Date      time,
        BCPGKey   key)
    {
        super(algorithm, time, key);
    }

    /**
     * Construct public subkey packet.
     *
     * @param algorithm public key algorithm
     * @param time creation time
     * @param key key
     */
    PublicSubkeyPacket(
            int version,
            int algorithm,
            Date time,
            BCPGKey key)
    {
        super(version, algorithm, time, key);
    }

    /**
     * Construct version 4 public subkey packet.
     *
     * @param algorithm public key algorithm
     * @param time creation time
     * @param key key
     */
    public static PublicSubkeyPacket createV4PublicSubKey(int algorithm, Date time, BCPGKey key)
    {
        return new PublicSubkeyPacket(VERSION_4, algorithm, time, key);
    }

    /**
     * Construct version 6 public subkey packet.
     *
     * @param algorithm public key algorithm
     * @param time creation time
     * @param key key
     */
    public static PublicSubkeyPacket createV6PublicSubKey(int algorithm, Date time, BCPGKey key)
    {
        return new PublicSubkeyPacket(VERSION_6, algorithm, time, key);
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(PUBLIC_SUBKEY, getEncodedContents());
    }
}
