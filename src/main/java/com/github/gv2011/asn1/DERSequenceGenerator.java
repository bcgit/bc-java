package com.github.gv2011.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * A stream generator for DER SEQUENCEs
 */
public class DERSequenceGenerator
    extends DERGenerator
{
    private final ByteArrayOutputStream _bOut = new ByteArrayOutputStream();

    /**
     * Use the passed in stream as the target for the generator.
     *
     * @param out target stream
     * @throws IOException if the target stream cannot be written to.
     */
    public DERSequenceGenerator(
        final OutputStream out)
        throws IOException
    {
        super(out);
    }

    /**
     * Use the passed in stream as the target for the generator, writing out the header tag
     * for a tagged constructed SEQUENCE (possibly implicit).
     *
     * @param out target stream
     * @param tagNo the tag number to introduce
     * @param isExplicit true if this is an explicitly tagged object, false otherwise.
     * @throws IOException if the target stream cannot be written to.
     */
    public DERSequenceGenerator(
        final OutputStream out,
        final int          tagNo,
        final boolean      isExplicit)
        throws IOException
    {
        super(out, tagNo, isExplicit);
    }

    /**
     * Add an object to the SEQUENCE being generated.
     *
     * @param object an ASN.1 encodable object to add.
     * @throws IOException if the target stream cannot be written to or the object cannot be encoded.
     */
    public void addObject(
        final ASN1Encodable object)
        throws IOException
    {
        object.toASN1Primitive().encode(new DEROutputStream(_bOut));
    }

    /**
     * Return the target stream for the SEQUENCE.
     *
     * @return  the OutputStream the SEQUENCE is being written to.
     */
    @Override
    public OutputStream getRawOutputStream()
    {
        return _bOut;
    }

    /**
     * Close of the generator, writing out the SEQUENCE.
     *
     * @throws IOException if the target stream cannot be written.
     */
    public void close()
        throws IOException
    {
        writeDEREncoded(BERTags.CONSTRUCTED | BERTags.SEQUENCE, _bOut.toByteArray());
    }
}
