package org.bouncycastle.tls;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public final class SessionID
    implements Comparable
{
    private final byte[] id;

    public SessionID(byte[] id)
    {
        this.id = Arrays.clone(id);
    }

    public int compareTo(Object o)
    {
        return Arrays.compareUnsigned(id, ((SessionID)o).id);
    }

    public boolean equals(Object obj)
    {
        if (!(obj instanceof SessionID))
        {
            return false;
        }
        SessionID other = (SessionID)obj;
        return Arrays.areEqual(id, other.id);
    }

    public byte[] getBytes()
    {
        return Arrays.clone(id);
    }

    public int hashCode()
    {
        return Arrays.hashCode(id);
    }

    public String toString()
    {
        return Hex.toHexString(id);
    }
}
