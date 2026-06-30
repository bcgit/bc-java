package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A stream generator for definite-length SEQUENCEs. The caller commits to the
 * total length of the SEQUENCE body up front; the header is written
 * immediately and the body then streams through {@link #getRawOutputStream()}
 * / {@link #addObject(ASN1Encodable)}. {@link #close()} verifies the body
 * came out at exactly the promised length and throws an {@link IOException}
 * otherwise — by then the output is not usable, but every length mismatch is
 * a caller arithmetic bug that must not pass silently.
 *
 * <p>Unlike {@link DERSequenceGenerator} nothing is buffered, so the body may
 * exceed the size of a Java array; the trade-off is that the length has to be
 * known before any content is produced.</p>
 */
public class DLSequenceGenerator
    extends DLGenerator
{
    private final ExactLengthOutputStream _body;

    /**
     * Use the passed in stream as the target for the generator, writing out
     * the header for a definite-length constructed SEQUENCE.
     *
     * @param out target stream
     * @param bodyLength the exact number of content octets that will be written
     * @throws IOException if the target stream cannot be written to.
     */
    public DLSequenceGenerator(OutputStream out, long bodyLength)
        throws IOException
    {
        super(out);

        writeDLHeader(BERTags.CONSTRUCTED | BERTags.SEQUENCE, bodyLength);
        _body = new ExactLengthOutputStream(out, bodyLength);
    }

    /**
     * Use the passed in stream as the target for the generator, writing out
     * the header for a tagged definite-length constructed SEQUENCE (possibly
     * implicit).
     *
     * @param out target stream
     * @param tagNo the tag number to introduce
     * @param isExplicit true if this is an explicitly tagged object, false otherwise.
     * @param bodyLength the exact number of content octets that will be written
     * @throws IOException if the target stream cannot be written to.
     */
    public DLSequenceGenerator(OutputStream out, int tagNo, boolean isExplicit, long bodyLength)
        throws IOException
    {
        super(out, tagNo, isExplicit);

        writeDLHeader(BERTags.CONSTRUCTED | BERTags.SEQUENCE, bodyLength);
        _body = new ExactLengthOutputStream(out, bodyLength);
    }

    /**
     * Return the target stream for the SEQUENCE body. Writes are counted
     * against the length declared at construction; writing past it fails
     * immediately.
     */
    public OutputStream getRawOutputStream()
    {
        return _body;
    }

    /**
     * Add the DL encoding of the passed in object to the SEQUENCE body.
     */
    public void addObject(ASN1Encodable object)
        throws IOException
    {
        object.toASN1Primitive().encodeTo(_body, ASN1Encoding.DL);
    }

    /**
     * Verify the declared body length was written in full.
     *
     * @throws IOException if fewer content octets were written than declared.
     */
    public void close()
        throws IOException
    {
        _body.finish();
    }
}
