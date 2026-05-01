package org.bouncycastle.bcpg;

/**
 * OpenPGP Packet Header Length Format.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-headers">
 * OpenPGP Packet Headers</a>
 */
public class PacketFormat
{
    /**
     * Always use the old (legacy) packet format.
     */
    public static final PacketFormat LEGACY = new PacketFormat(0);

    /**
     * Always use the current (new) packet format.
     */
    public static final PacketFormat CURRENT = new PacketFormat(1);

    /**
     * Let the individual packet decide the format (see {@link Packet#hasNewPacketFormat()}).
     * This allows to round-trip packets without changing the packet format.
     */
    public static final PacketFormat ROUNDTRIP = new PacketFormat(2);

    private final int ord;

    private PacketFormat(int ord)
    {
        this.ord = ord;
    }
}
