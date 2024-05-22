package org.bouncycastle.bcpg;

/**
 * OpenPGP Packet Header Length Format.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-packet-headers">
 * OpenPGP Packet Headers</a>
 */
public enum PacketFormat
{
    /**
     * Always use the old (legacy) packet format.
     */
    LEGACY,

    /**
     * Always use the current (new) packet format.
     */
    CURRENT,

    /**
     * Let the individual packet decide the format (see {@link Packet#hasNewPacketFormat()}).
     * This allows to round-trip packets without changing the packet format.
     */
    ROUNDTRIP
}
