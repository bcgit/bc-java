package org.bouncycastle.openpgp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;

/**
 * A holder for a list of PGP encryption method packets.
 */
public class PGPEncryptedDataList
{
    List                 list = new ArrayList();
    InputStreamPacket    data;
    
    public PGPEncryptedDataList(
        BCPGInputStream    pIn)
        throws IOException
    {
        while (pIn.nextPacketTag() == PacketTags.PUBLIC_KEY_ENC_SESSION
            || pIn.nextPacketTag() == PacketTags.SYMMETRIC_KEY_ENC_SESSION)
        {
            list.add(pIn.readPacket());
        }

        data = (InputStreamPacket)pIn.readPacket();
        
        for (int i = 0; i != list.size(); i++)
        {
            if (list.get(i) instanceof SymmetricKeyEncSessionPacket)
            {
                list.set(i, new PGPPBEEncryptedData((SymmetricKeyEncSessionPacket)list.get(i), data));
            }
            else 
            {
                list.set(i, new PGPPublicKeyEncryptedData((PublicKeyEncSessionPacket)list.get(i), data));
            }
        }
    }
    
    public Object get(
        int    index)
    {
        return list.get(index);
    }
    
    public int size()
    {
        return list.size();
    }
    
    public boolean isEmpty()
    {
        return list.isEmpty();
    }
    
    /**
     * @deprecated misspelt - use getEncryptedDataObjects()
     */
    public Iterator getEncyptedDataObjects()
    {
        return list.iterator();
    }
    
    public Iterator getEncryptedDataObjects()
    {
        return list.iterator();
    }
}
