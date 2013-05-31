package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.bcpg.UserAttributeSubpacketTags;
import org.bouncycastle.bcpg.attr.ImageAttribute;

/**
 * Container for a list of user attribute subpackets.
 */
public class PGPUserAttributeSubpacketVector
{
    UserAttributeSubpacket[]        packets;
    
    PGPUserAttributeSubpacketVector(
        UserAttributeSubpacket[]    packets)
    {
        this.packets = packets;
    }
    
    public UserAttributeSubpacket getSubpacket(
        int    type)
    {
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].getType() == type)
            {
                return packets[i];
            }
        }
        
        return null;
    }
    
    public ImageAttribute getImageAttribute()
    {
        UserAttributeSubpacket    p = this.getSubpacket(UserAttributeSubpacketTags.IMAGE_ATTRIBUTE);
        
        if (p == null)
        {
            return null;
        }
                    
        return (ImageAttribute)p;
    }
    
    UserAttributeSubpacket[] toSubpacketArray()
    {
        return packets;
    }
    
    public boolean equals(
        Object o)
    {
        if (o == this)
        {
            return true;
        }
        
        if (o instanceof PGPUserAttributeSubpacketVector)
        {
            PGPUserAttributeSubpacketVector    other = (PGPUserAttributeSubpacketVector)o;
            
            if (other.packets.length != packets.length)
            {
                return false;
            }
            
            for (int i = 0; i != packets.length; i++)
            {
                if (!other.packets[i].equals(packets[i]))
                {
                    return false;
                }
            }
            
            return true;
        }
        
        return false;
    }
    
    public int hashCode()
    {
        int    code = 0;
        
        for (int i = 0; i != packets.length; i++)
        {
            code ^= packets[i].hashCode();
        }
        
        return code;
    }
}
