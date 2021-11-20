package org.bouncycastle.asn1.cms;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.ASN1Util;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-3">RFC 5652</a> {@link ContentInfo} object parser.
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
            // TODO[cms] Ideally we could enforce the claimed tag
//            return ASN1Util.parseContextBaseUniversal(content, 0, true, tag);
            return ASN1Util.parseExplicitContextBaseObject(content, 0);
        }

        return null;
    }
}
