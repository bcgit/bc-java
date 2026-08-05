package org.bouncycastle.gpg.keybox;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

/**
 * A PGP blob holds key material.
 */
public class PublicKeyRingBlob
    extends KeyBlob
{
    private final KeyFingerPrintCalculator fingerPrintCalculator;

    private PublicKeyRingBlob(int base, long length,
                              BlobType type,
                              int version,
                              KeyBlobContent content,
                              KeyFingerPrintCalculator fingerPrintCalculator)
    {
        super(base, length, type, version, content);
        this.fingerPrintCalculator = fingerPrintCalculator;
    }


    static Blob parseContent(int base, long length, BlobType type, int version, KeyBoxByteBuffer buffer, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier blobVerifier)
        throws IOException
    {

        KeyBlobContent content = KeyBlobContent.parse(base, length, buffer, blobVerifier);

        return new PublicKeyRingBlob(base, length, type, version, content, fingerPrintCalculator);
    }

    /**
     * Return the gpg public key ring from the key box blob.
     *
     * @return A new PGPPublicKeyRing based on the blobs raw data.
     * @throws IOException if the data cannot be parsed.
     * @throws IllegalStateException if the blob is not BlobType.OPEN_PGP_BLOB
     */
    public PGPPublicKeyRing getPGPPublicKeyRing()
        throws IOException
    {
        if (this.type == BlobType.OPEN_PGP_BLOB)
        {
            return new PGPPublicKeyRing(
                getKeyBytes(), fingerPrintCalculator);
        }

        throw new IllegalStateException("Blob is not PGP blob, it is " + type.name());
    }
}
