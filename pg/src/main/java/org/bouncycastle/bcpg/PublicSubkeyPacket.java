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
     * Construct version 4 public key packet.
     * 
     * @param algorithm
     * @param time
     * @param key
     */
    public PublicSubkeyPacket(
        int       algorithm,
        Date      time,
        BCPGKey   key)
    {
        super(algorithm, time, key);
    }

    public PublicSubkeyPacket(
            int version,
            int algorithm,
            Date time,
            BCPGKey key)
    {
        super(version, algorithm, time, key);
    }

    public static PublicSubkeyPacket createV4PublicSubKey(int algorithm, Date time, BCPGKey key)
    {
        return new PublicSubkeyPacket(4, algorithm, time, key);
    }

    public static PublicSubkeyPacket createV5PublicSubKey(int algorithm, Date time, BCPGKey key)
    {
        return new PublicSubkeyPacket(5, algorithm, time, key);
    }

    public static PublicSubkeyPacket createV6PublicSubKey(int algorithm, Date time, BCPGKey key)
    {
        return new PublicSubkeyPacket(6, algorithm, time, key);
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(PUBLIC_SUBKEY, getEncodedContents());
    }
}
