package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Basic type for a PGP packet.
 */
public abstract class ContainedPacket 
    extends Packet implements Encodeable
{
    public byte[] getEncoded() 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream         pOut = new BCPGOutputStream(bOut);
        
        pOut.writePacket(this);
        
        pOut.close();
        
        return BCPGUtil.getEncoded(this);
    }
    
}
