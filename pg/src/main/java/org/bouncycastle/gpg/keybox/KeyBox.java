package org.bouncycastle.gpg.keybox;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

/**
 * KeyBox provides an implementation of the PGP keybox.
 */
public class KeyBox
{
    private final FirstBlob firstBlob;
    private final List<KeyBlob> keyBlobs;

    public KeyBox(InputStream input, KeyFingerPrintCalculator keyFingerPrintCalculator, BlobVerifier blobVerifier)
        throws IOException
    {
        this(KeyBoxByteBuffer.wrap(input), keyFingerPrintCalculator, blobVerifier);
    }

    public KeyBox(byte[] encoding, KeyFingerPrintCalculator keyFingerPrintCalculator, BlobVerifier blobVerifier)
        throws IOException
    {
        this(KeyBoxByteBuffer.wrap(encoding), keyFingerPrintCalculator, blobVerifier);
    }

    private KeyBox(KeyBoxByteBuffer buffer, KeyFingerPrintCalculator keyFingerPrintCalculator, BlobVerifier blobVerifier)
        throws IOException
    {
        Blob blob = Blob.getInstance(buffer, keyFingerPrintCalculator, blobVerifier);
        if (blob == null)
        {
            throw new IOException("No first blob, is the source zero length?");
        }

        if (!(blob instanceof FirstBlob))
        {
            throw new IOException("First blob is not KeyBox 'First Blob'.");
        }


        FirstBlob firstBlob = (FirstBlob)blob;
        ArrayList<KeyBlob> keyBoxEntries = new ArrayList<KeyBlob>();

        for (Blob materialBlob = Blob.getInstance(buffer, keyFingerPrintCalculator, blobVerifier);
             materialBlob != null; materialBlob = Blob.getInstance(buffer, keyFingerPrintCalculator, blobVerifier))
        {
            if (materialBlob.getType() == BlobType.FIRST_BLOB)
            {
                throw new IOException("Unexpected second 'FirstBlob', there should only be one FirstBlob at the start of the file.");
            }

            keyBoxEntries.add((KeyBlob)materialBlob);
        }

        this.firstBlob = firstBlob;
        this.keyBlobs = Collections.unmodifiableList(keyBoxEntries);
    }

    public FirstBlob getFirstBlob()
    {
        return firstBlob;
    }

    public List<KeyBlob> getKeyBlobs()
    {
        return keyBlobs;
    }

}
