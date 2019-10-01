package org.bouncycastle.gpg.keybox;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

public class KeyInformation
{
    private final byte[] fingerprint;
    private final long offsetToKeyID;
    private final int keyFlags;
    private final byte[] filler;
    private final byte[] keyID;

    KeyInformation(byte[] fingerprint, long offsetToKeyID, int keyFlags, byte[] filler, byte[] keyID)
    {
        this.fingerprint = Arrays.clone(fingerprint);
        this.offsetToKeyID = offsetToKeyID;
        this.keyFlags = keyFlags;
        this.filler = Arrays.clone(filler);
        this.keyID = Arrays.clone(keyID);
    }

    static KeyInformation getInstance(Object src, int expectedSize, int base)
        throws IOException
    {

        if (src instanceof KeyInformation)
        {
            return (KeyInformation)src;
        }


        KeyBoxByteBuffer buffer = KeyBoxByteBuffer.wrap(src);


        int start = buffer.position();

        byte[] fingerPrint =  buffer.bN(20);// The keys fingerprint

        long offsetToKeyID = buffer.u32();  // offset to the n-th key's keyID (a keyID is always 8 byte)
        // or 0 if not known which is the case only for X509.
        byte[] keyID = null;

        if (offsetToKeyID > 0)
        {
            keyID = buffer.rangeOf((int)(base + offsetToKeyID), (int)(base + offsetToKeyID + 8));
        }


        int keyFlags = buffer.u16(); // key flags,  bit 0 = qualified signature (not yet implemented}
        buffer.u16();  // RFU = Reserved for Future Use

        byte[] filler = buffer.bN(expectedSize - (buffer.position() - start));


        return new KeyInformation(fingerPrint, offsetToKeyID, keyFlags, filler, keyID);

    }

    public byte[] getFingerprint()
    {
        return Arrays.clone(fingerprint);
    }

    public int getKeyFlags()
    {
        return keyFlags;
    }

    public byte[] getFiller()
    {
        return Arrays.clone(filler);
    }

    public byte[] getKeyID()
    {
        return Arrays.clone(keyID);
    }
}
