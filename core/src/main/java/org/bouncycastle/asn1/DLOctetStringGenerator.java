package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A stream generator for definite-length (primitive) OCTET STRINGs. The
 * caller commits to the octet count up front; the header is written
 * immediately and the octets then stream through
 * {@link #getOctetOutputStream()}, which enforces the count — writing past it
 * fails immediately, and {@link #close()} fails if it was not reached. The
 * count is a {@code long}, so content larger than a Java array can carry is
 * supported.
 *
 * <p>The result is a single primitive OCTET STRING (as DER requires), in
 * contrast to {@link BEROctetStringGenerator}'s indefinite-length constructed
 * chunking.</p>
 */
public class DLOctetStringGenerator
    extends DLGenerator
{
    private final ExactLengthOutputStream _octets;

    /**
     * Use the passed in stream as the target for the generator, writing out
     * the header for a definite-length primitive OCTET STRING.
     *
     * @param out target stream
     * @param octetCount the exact number of octets that will be written
     * @throws IOException if the target stream cannot be written to.
     */
    public DLOctetStringGenerator(OutputStream out, long octetCount)
        throws IOException
    {
        super(out);

        writeDLHeader(BERTags.OCTET_STRING, octetCount);
        _octets = new ExactLengthOutputStream(out, octetCount);
    }

    /**
     * Use the passed in stream as the target for the generator, writing out
     * the header for a tagged definite-length OCTET STRING (primitive when
     * implicit, per X.690 8.14.3).
     *
     * @param out target stream
     * @param tagNo the tag number to introduce
     * @param isExplicit true if this is an explicitly tagged object, false otherwise.
     * @param octetCount the exact number of octets that will be written
     * @throws IOException if the target stream cannot be written to.
     */
    public DLOctetStringGenerator(OutputStream out, int tagNo, boolean isExplicit, long octetCount)
        throws IOException
    {
        super(out, tagNo, isExplicit);

        writeDLHeader(BERTags.OCTET_STRING, octetCount);
        _octets = new ExactLengthOutputStream(out, octetCount);
    }

    /**
     * Return the content target for this OCTET STRING. Writes are counted
     * against the count declared at construction; writing past it fails
     * immediately.
     */
    public OutputStream getOctetOutputStream()
    {
        return _octets;
    }

    /**
     * Verify the declared octet count was written in full.
     *
     * @throws IOException if fewer octets were written than declared.
     */
    public void close()
        throws IOException
    {
        _octets.finish();
    }
}
