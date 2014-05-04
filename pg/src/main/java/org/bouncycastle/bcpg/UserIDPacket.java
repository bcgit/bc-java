package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Basic type for a user ID packet.
 */
public class UserIDPacket 
    extends ContainedPacket
{    
    private byte[]    idData;
    
    public UserIDPacket(
        BCPGInputStream  in)
        throws IOException
    {
        this.idData = in.readAll();
    }

    public UserIDPacket(
        String    id)
    {
        this.idData = Strings.toUTF8ByteArray(id);
    }

    public UserIDPacket(byte[] rawID)
    {
        this.idData = Arrays.clone(rawID);
    }

    public String getID()
    {
        return Strings.fromUTF8ByteArray(idData);
    }

    public byte[] getRawID()
    {
        return Arrays.clone(idData);
    }

    public boolean equals(Object o)
    {
        if (o instanceof UserIDPacket)
        {
            return Arrays.areEqual(this.idData, ((UserIDPacket)o).idData);
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(this.idData);
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(USER_ID, idData, true);
    }
}
