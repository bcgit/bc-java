package org.bouncycastle.jcajce.io;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.Signature;

import javax.crypto.Mac;

/**
 * Utility class for creating OutputStreams from different JCA/JCE operators.
 */
public class OutputStreamFactory
{
    /**
     * Create an OutputStream that wraps a signature.
     *
     * @param signature the signature to be updated as the stream is written to.
     * @return an OutputStream.
     */
    public static OutputStream createStream(Signature signature)
    {
        return new SignatureUpdatingOutputStream(signature);
    }

    /**
     * Create an OutputStream that wraps a digest.
     *
     * @param digest the digest to be updated as the stream is written to.
     * @return an OutputStream.
     */
    public static OutputStream createStream(MessageDigest digest)
    {
        return new DigestUpdatingOutputStream(digest);
    }

    /**
     * Create an OutputStream that wraps a mac.
     *
     * @param mac the signature to be updated as the stream is written to.
     * @return an OutputStream.
     */
    public static OutputStream createStream(Mac mac)
    {
        return new MacUpdatingOutputStream(mac);
    }
}
