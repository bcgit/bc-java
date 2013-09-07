package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Output Basic Encoding Rule (See X.690 chapter 8) format SEQUENCE.
 * <p>
 * See {@link BERGenerator} about basic encoder details.
 */
public class BERSequenceGenerator
    extends BERGenerator
{
    public BERSequenceGenerator(
        OutputStream out) 
        throws IOException
    {
        super(out);

        writeBERHeader(BERTags.CONSTRUCTED | BERTags.SEQUENCE);
    }

    public BERSequenceGenerator(
        OutputStream out,
        int tagNo,
        boolean isExplicit) 
        throws IOException
    {
        super(out, tagNo, isExplicit);
        
        writeBERHeader(BERTags.CONSTRUCTED | BERTags.SEQUENCE);
    }

    public void addObject(
        ASN1Encodable object)
        throws IOException
    {
        object.toASN1Primitive().encode(new BEROutputStream(_out));
    }
    
    public void close() 
        throws IOException
    {
        writeBEREnd();
    }
}
