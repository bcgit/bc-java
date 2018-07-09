package org.bouncycastle.gpg.keybox;

/**
 * Base interface for a blob integrity checking operator.
 */
public interface BlobVerifier
{
    /**
     * Return true if the passed in blobData calculates to the expected digest.
     *
     * @param blobData   bytes making up the blob.
     * @param blobDigest the expected digest.
     * @return true on a match, false otherwise.
     */
    boolean isMatched(byte[] blobData, byte[] blobDigest);
}
