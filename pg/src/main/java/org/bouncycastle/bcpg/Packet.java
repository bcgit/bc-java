package org.bouncycastle.bcpg;

/**
 */
public abstract class Packet
    implements PacketTags
{

    /**
     * Return the tag of the packet.
     *
     * @return packet tag
     */
    public abstract int getPacketTag();

    /**
     * Returns whether the packet is to be considered critical for v6 implementations.
     * Packets with tags less or equal to 39 are critical.
     * Tags 40 to 59 are reserved for unassigned, non-critical packets.
     * Tags 60 to 63 are non-critical private or experimental packets.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-09.html#name-packet-tags">
     *     Packet Tags</a>
     * @return true if the packet is critical, false otherwise.
     */
    public boolean isCritical()
    {
        return getPacketTag() <= 39;
    }
}
