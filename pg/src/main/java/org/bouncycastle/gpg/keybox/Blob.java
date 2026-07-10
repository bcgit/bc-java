package org.bouncycastle.gpg.keybox;

import java.io.IOException;

import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.util.Strings;

/**
 * GnuPG keybox blob.
 * Based on:
 *
 * @see <a href="https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=kbx/keybox-blob.c;hb=HEAD"></a>
 */

public class Blob
{
    protected static final byte[] magicBytes = Strings.toByteArray("KBXf");

    protected final int base; // position from start of keybox file.
    protected final long length;
    protected final BlobType type;
    protected final int version;

    protected Blob(int base, long length, BlobType type, int version)
    {
        this.base = base;
        this.length = length;
        this.type = type;
        this.version = version;
    }


    /**
     * Return an instance of a blob from the source.
     * Will return null if no more blobs exist.
     *
     * @param source The source, KeyBoxByteBuffer, ByteBuffer, byte[], InputStream or File.
     * @return
     * @throws Exception
     */
    static Blob getInstance(Object source, KeyFingerPrintCalculator keyFingerPrintCalculator, BlobVerifier blobVerifier)
        throws IOException
    {
        if (source == null)
        {
            throw new IllegalArgumentException("Cannot take get instance of null");
        }

        KeyBoxByteBuffer buffer = KeyBoxByteBuffer.wrap(source);

        for (;;)
        {
            if (!buffer.hasRemaining())
            {
                return null;
            }

            int base = buffer.position();
            long len = buffer.u32();
            BlobType type = BlobType.fromByte(buffer.u8());
            int version = buffer.u8();

            switch (type)
            {

            case EMPTY_BLOB:
                // An empty blob is a free/deleted slot occupying len bytes - it is NOT
                // end-of-file, so skip past it and continue with the following blobs (a keybox
                // written by gnupg can carry an empty blob between real ones); github #2343.
                // The header just read is 6 bytes (u32 length + u8 type + u8 version), so a
                // well-formed blob has next = base + len >= base + 6 = the current position. A
                // header-only empty blob (len == 6) is legal and must be skipped; only a length
                // that would move the position backwards (len < 6, failing to advance / spinning
                // forever) or point beyond the buffer is malformed.
                long next = base + len;
                if (next < buffer.position() || next > (buffer.position() + buffer.remaining()))
                {
                    return null;
                }
                buffer.position((int)next);
                continue;
            case FIRST_BLOB:
                return FirstBlob.parseContent(base, len, type, version, buffer);
            case X509_BLOB:
                return CertificateBlob.parseContent(base, len, type, version, buffer, blobVerifier);
            case OPEN_PGP_BLOB:
                return PublicKeyRingBlob.parseContent(base, len, type, version, buffer, keyFingerPrintCalculator, blobVerifier);
            }

            return null;
        }
    }


    public BlobType getType()
    {
        return type;
    }

    public int getVersion()
    {
        return version;
    }


}
