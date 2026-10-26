package org.bouncycastle.openpgp;

import java.util.Comparator;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.bcpg.UserIDPacket;
import org.bouncycastle.util.Arrays;

/**
 * Total orders on the packets a merge indexes, each agreeing with the packet's equals(), so that the
 * index can be an ordered tree rather than a hash table. Every field of these packets is chosen by
 * whoever wrote the copy being merged, and so is its hash code: a copy flooded with user IDs, user
 * attributes or unhashed subpackets that all share one hash code drives a hash table's lookups back
 * to a scan of the bucket - and the merge back to quadratic - where a tree stays at log n.
 */
final class MergeOrder
{
    /** Signature subpackets by type, criticality and then data, as {@link SignatureSubpacket#equals}. */
    static final Comparator SIGNATURE_SUBPACKET = new Comparator()
    {
        public int compare(Object a, Object b)
        {
            SignatureSubpacket sa = (SignatureSubpacket)a;
            SignatureSubpacket sb = (SignatureSubpacket)b;
            if (sa.getType() != sb.getType())
            {
                return sa.getType() < sb.getType() ? -1 : 1;
            }
            if (sa.isCritical() != sb.isCritical())
            {
                return sa.isCritical() ? 1 : -1;
            }
            return Arrays.compareUnsigned(sa.getData(), sb.getData());
        }
    };

    /**
     * User IDs and user attributes: user IDs first, by their raw bytes; user attribute vectors by
     * their subpackets, each by type and then data - the fields {@link UserIDPacket#equals} and
     * {@link PGPUserAttributeSubpacketVector#equals} compare.
     */
    static final Comparator USER_DATA = new Comparator()
    {
        public int compare(Object a, Object b)
        {
            int kindA = kind(a);
            int kindB = kind(b);
            if (kindA != kindB)
            {
                return kindA < kindB ? -1 : 1;
            }
            switch (kindA)
            {
            case 0:
                return Arrays.compareUnsigned(((UserIDPacket)a).getRawID(), ((UserIDPacket)b).getRawID());
            case 1:
                return compareSubpackets(((PGPUserAttributeSubpacketVector)a).toSubpacketArray(),
                    ((PGPUserAttributeSubpacketVector)b).toSubpacketArray());
            case 2:
                return compareSubpackets(((UserAttributePacket)a).getSubpackets(),
                    ((UserAttributePacket)b).getSubpackets());
            default:
                // no other user data packet type exists; keep equals() consistent and the rest stable
                if (a.equals(b))
                {
                    return 0;
                }
                int ha = System.identityHashCode(a);
                int hb = System.identityHashCode(b);
                return ha < hb ? -1 : 1;
            }
        }
    };

    private static int kind(Object packet)
    {
        if (packet instanceof UserIDPacket)
        {
            return 0;
        }
        if (packet instanceof PGPUserAttributeSubpacketVector)
        {
            return 1;
        }
        if (packet instanceof UserAttributePacket)
        {
            return 2;
        }
        return 3;
    }

    private static int compareSubpackets(UserAttributeSubpacket[] a, UserAttributeSubpacket[] b)
    {
        if (a.length != b.length)
        {
            return a.length < b.length ? -1 : 1;
        }
        for (int i = 0; i != a.length; i++)
        {
            if (a[i].getType() != b[i].getType())
            {
                return a[i].getType() < b[i].getType() ? -1 : 1;
            }
            int c = Arrays.compareUnsigned(a[i].getData(), b[i].getData());
            if (c != 0)
            {
                return c;
            }
        }
        return 0;
    }

    static int compareLongs(long a, long b)
    {
        return a < b ? -1 : (a == b ? 0 : 1);
    }

    private MergeOrder()
    {
    }
}
