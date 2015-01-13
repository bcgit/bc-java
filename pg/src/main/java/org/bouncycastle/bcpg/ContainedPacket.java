package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Encodable;

/**
 * Basic type for a PGP packet.
 */
public abstract class ContainedPacket 
    extends Packet
    implements Encodable
{
    public byte[] getEncoded() 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream         pOut = new BCPGOutputStream(bOut);
        
        pOut.writePacket(this);

        pOut.close();

        return bOut.toByteArray();
    }
    
    public abstract void encode(
        BCPGOutputStream    pOut)
        throws IOException;
}
