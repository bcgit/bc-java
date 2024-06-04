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
        this(in, false);
    }

    PublicSubkeyPacket(
        BCPGInputStream    in,
        boolean newPacketFormat)
        throws IOException
    {      
        super(PUBLIC_SUBKEY, in, newPacketFormat);
    }
    
    /**
     * Construct version 4 public sub-key packet.
     * 
     * @param algorithm
     * @param time
     * @param key
     * @deprecated use versioned {@link #PublicSubkeyPacket(int, int, Date, BCPGKey)} instead
     */
    @Deprecated
    public PublicSubkeyPacket(
        int       algorithm,
        Date      time,
        BCPGKey   key)
    {
        this(VERSION_4, algorithm, time, key);
    }

    /**
     * Construct a public sub-key packet.
     *
     * @param version
     * @param algorithm
     * @param time
     * @param key
     */
    public PublicSubkeyPacket(
        int version,
        int       algorithm,
        Date      time,
        BCPGKey   key)
    {
        super(PUBLIC_SUBKEY, version, algorithm, time, key);
    }
}
