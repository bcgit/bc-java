package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Integers;

/**
 * Signature Subpacket encoding the capabilities / intended uses of a key.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.21">
 *     RFC4880 - Key Flags</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-key-flags">
 *     RFC9580 - Key Flags</a>
 */
public class KeyFlags 
    extends SignatureSubpacket
{
    /**
     * This key may be used to make User ID certifications (signature type IDs 0x10-0x13)
     * or direct key signatures (signature type ID 0x1F) over other peoples keys.
     */
    public static final int CERTIFY_OTHER = 0x01;

    /**
     * This key may be used to sign data.
     */
    public static final int SIGN_DATA = 0x02;

    /**
     * This key may be used to encrypt communications.
     */
    public static final int ENCRYPT_COMMS = 0x04;

    /**
     * This key may be used to encrypt storage.
     */
    public static final int ENCRYPT_STORAGE = 0x08;

    /**
     * The private component of this key may have been split by a secret-sharing mechanism.
     */
    public static final int SPLIT = 0x10;

    /**
     * This key may be used for authentication.
     */
    public static final int AUTHENTICATION = 0x20;

    /**
     * The private component of this key may be in the possession of more than one person.
     */
    public static final int SHARED = 0x80;

    private static int dataToFlags(byte[] data)
    {
        int flags = 0, bytes = Math.min(4, data.length);
        for (int i = 0; i < bytes; ++i)
        {
            flags |= (data[i] & 0xFF) << (i * 8);
        }
        return flags;
    }

    private static byte[] flagsToData(int flags)
    {
        int bits = 32 - Integers.numberOfLeadingZeros(flags);
        int bytes = (bits + 7) / 8;

        byte[] data = new byte[bytes];
        for (int i = 0; i < bytes; ++i)
        {
            data[i] = (byte)(flags >> (i * 8));
        }
        return data;
    }

    public KeyFlags(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.KEY_FLAGS, critical, isLongLength, data);
    }
    
    public KeyFlags(
        boolean    critical,
        int        flags)
    {
        super(SignatureSubpacketTags.KEY_FLAGS, critical, false, flagsToData(flags));
    }

    /**
     * Return the flag values contained in the first 4 octets (note: at the moment
     * the standard only uses the first one).
     *
     * @return flag values.
     */
    public int getFlags()
    {
        return dataToFlags(data);
    }
}
