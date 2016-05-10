package com.github.gv2011.bcasn.asn1.cms;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1Encodable;
import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1OctetStringParser;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.ASN1SequenceParser;
import com.github.gv2011.bcasn.asn1.DERIA5String;

/**
 * Parser for <a href="http://tools.ietf.org/html/rfc5544">RFC 5544</a>:
 * {@link TimeStampedData} object.
 * <p>
 * <pre>
 * TimeStampedData ::= SEQUENCE {
 *   version              INTEGER { v1(1) },
 *   dataUri              IA5String OPTIONAL,
 *   metaData             MetaData OPTIONAL,
 *   content              OCTET STRING OPTIONAL,
 *   temporalEvidence     Evidence
 * }
 * </pre>
 */
public class TimeStampedDataParser
{
    private ASN1Integer version;
    private DERIA5String dataUri;
    private MetaData metaData;
    private ASN1OctetStringParser content;
    private Evidence temporalEvidence;
    private ASN1SequenceParser parser;

    private TimeStampedDataParser(ASN1SequenceParser parser)
        throws IOException
    {
        this.parser = parser;
        this.version = ASN1Integer.getInstance(parser.readObject());

        ASN1Encodable obj = parser.readObject();

        if (obj instanceof DERIA5String)
        {
            this.dataUri = DERIA5String.getInstance(obj);
            obj = parser.readObject();
        }
        if (obj instanceof MetaData || obj instanceof ASN1SequenceParser)
        {
            this.metaData = MetaData.getInstance(obj.toASN1Primitive());
            obj = parser.readObject();
        }
        if (obj instanceof ASN1OctetStringParser)
        {
            this.content = (ASN1OctetStringParser)obj;
        }
    }

    public static TimeStampedDataParser getInstance(Object obj)
        throws IOException
    {
        if (obj instanceof ASN1Sequence)
        {
            return new TimeStampedDataParser(((ASN1Sequence)obj).parser());
        }
        if (obj instanceof ASN1SequenceParser)
        {
            return new TimeStampedDataParser((ASN1SequenceParser)obj);
        }

        return null;
    }

    public DERIA5String getDataUri()
    {
        return dataUri;
    }

    public MetaData getMetaData()
    {
        return metaData;
    }

    public ASN1OctetStringParser getContent()
    {
        return content;
    }

    public Evidence getTemporalEvidence()
        throws IOException
    {
        if (temporalEvidence == null)
        {
            temporalEvidence = Evidence.getInstance(parser.readObject().toASN1Primitive());
        }

        return temporalEvidence;
    }
}
