package com.github.gv2011.bcasn.asn1.cms;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1Encodable;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1SequenceParser;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObjectParser;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-3">RFC 5652</a> {@link ContentInfo} object parser.
 *
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 * </pre>
 */
public class ContentInfoParser
{
    private ASN1ObjectIdentifier contentType;
    private ASN1TaggedObjectParser content;

    public ContentInfoParser(
        ASN1SequenceParser seq)
        throws IOException
    {
        contentType = (ASN1ObjectIdentifier)seq.readObject();
        content = (ASN1TaggedObjectParser)seq.readObject();
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public ASN1Encodable getContent(
        int  tag)
        throws IOException
    {
        if (content != null)
        {
            return content.getObjectParser(tag, true);
        }

        return null;
    }
}
