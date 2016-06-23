package org.bouncycastle.asn1;

import java.io.OutputStream;

/**
 * Basic class for streaming generators.
 */
public abstract class ASN1Generator
{
    protected OutputStream _out;

    /**
     * Base constructor.
     *
     * @param out the end output stream that object encodings are written to.
     */
    public ASN1Generator(OutputStream out)
    {
        _out = out;
    }

    /**
     * Return the actual stream object encodings are written to.
     *
     * @return the stream that is directly encoded to.
     */
    public abstract OutputStream getRawOutputStream();
}
