package org.bouncycastle.bcpg;

/**
 */
public class Packet
    implements PacketTags
{
    private final int packetTag;
    private final boolean newPacketFormat;

    // for API compatibility
    public Packet()
    {
        this(RESERVED);
    }

    Packet(int packetTag)
    {
        this(packetTag, false);
    }

    Packet(int packetTag, boolean newPacketFormat)
    {
        this.packetTag = packetTag;
        this.newPacketFormat = newPacketFormat;
    }

    /**
     * Return the tag of the packet.
     *
     * @return packet tag
     */
    public final int getPacketTag()
    {
         return packetTag;
    }

    /**
     * Return true, if this instance of a packet was encoded using the new packet format.
     * If the packet was encoded using the old legacy format, return false instead.
     *
     * @return true if new packet format encoding is used
     */
    public boolean hasNewPacketFormat()
    {
        return newPacketFormat;
    }

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
