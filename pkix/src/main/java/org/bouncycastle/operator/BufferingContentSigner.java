package org.bouncycastle.operator;

import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.io.BufferingOutputStream;

/**
 * A class that explicitly buffers the data to be signed, sending it in one
 * block when ready for signing.
 */
public class BufferingContentSigner
    implements ContentSigner
{
    private final ContentSigner contentSigner;
    private final OutputStream  output;

    /**
     * Base constructor.
     *
     * @param contentSigner the content signer to be wrapped.
     */
    public BufferingContentSigner(ContentSigner contentSigner)
    {
        this.contentSigner = contentSigner;
        this.output = new BufferingOutputStream(contentSigner.getOutputStream());
    }

    /**
     * Base constructor.
     *
     * @param contentSigner the content signer to be wrapped.
     * @param bufferSize the size of the internal buffer to use.
     */
    public BufferingContentSigner(ContentSigner contentSigner, int bufferSize)
    {
        this.contentSigner = contentSigner;
        this.output = new BufferingOutputStream(contentSigner.getOutputStream(), bufferSize);
    }

    /**
     * Return the algorithm identifier supported by this signer.
     *
     * @return algorithm identifier for the signature generated.
     */
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return contentSigner.getAlgorithmIdentifier();
    }

    /**
     * Return the buffering stream.
     *
     * @return the output stream used to accumulate the data.
     */
    public OutputStream getOutputStream()
    {
        return output;
    }

    /**
     * Generate signature from internally buffered data.
     *
     * @return the signature calculated from the bytes written to the buffering stream.
     */
    public byte[] getSignature()
    {
        return contentSigner.getSignature();
    }

    @Override
    public void close() throws Exception
    {
        output.close();
        if (contentSigner != null)
        {
            contentSigner.close();
        }
    }
}
