package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

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
    
    private static byte[] intToByteArray(
        int    v)
    {
        byte[] tmp = new byte[4];
        int    size = 0;

        for (int i = 0; i != 4; i++)
        {
            tmp[i] = (byte)(v >> (i * 8));
            if (tmp[i] != 0)
            {
                size = i;
            }
        }

        byte[]    data = new byte[size + 1];
        
        System.arraycopy(tmp, 0, data, 0, data.length);

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
        super(SignatureSubpacketTags.KEY_FLAGS, critical, false, intToByteArray(flags));
    }

    /**
     * Return the flag values contained in the first 4 octets (note: at the moment
     * the standard only uses the first one).
     *
     * @return flag values.
     */
    public int getFlags()
    {
        int flags = 0;

        for (int i = 0; i != data.length; i++)
        {
            flags |= (data[i] & 0xff) << (i * 8);
        }

        return flags;
    }
}
