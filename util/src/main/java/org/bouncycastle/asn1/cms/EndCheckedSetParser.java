package org.bouncycastle.asn1.cms;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1SetParser;

/**
 * The parser of the last SET field of a streamed SEQUENCE: once the set has been read to its
 * end, the enclosing sequence is checked for an element after it, which the structure does not
 * allow (github #2516). The check runs once, on whichever of readObject(), getLoadedObject() or
 * toASN1Primitive() reaches the end of the set first.
 */
class EndCheckedSetParser
    implements ASN1SetParser
{
    private final ASN1SetParser set;
    private final ASN1SequenceParser seq;
    private final String message;
    private boolean checked;

    EndCheckedSetParser(ASN1SetParser set, ASN1SequenceParser seq, String owner, String field)
    {
        this.set = set;
        this.seq = seq;
        this.message = owner + " has an unexpected element after " + field;
    }

    public ASN1Encodable readObject()
        throws IOException
    {
        ASN1Encodable o = set.readObject();
        if (o == null)
        {
            checkEnd();
        }
        return o;
    }

    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        ASN1Primitive p = set.getLoadedObject();
        checkEnd();
        return p;
    }

    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException(e.getMessage(), e);
        }
    }

    private void checkEnd()
        throws IOException
    {
        if (!checked)
        {
            checked = true;
            if (seq.readObject() != null)
            {
                throw new IOException(message);
            }
        }
    }
}
