package org.bouncycastle.asn1.microsoft;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.ContentInfo;

/**
 * The Microsoft Authenticode time stamp request, as sent to a legacy
 * (pre-RFC 3161) Authenticode time stamping service (the protocol behind
 * {@code signtool /t}; the RFC 3161 protocol is {@code signtool /tr}).
 * <pre>
 * TimeStampRequest ::= SEQUENCE {
 *    countersignatureType OBJECT IDENTIFIER,
 *    attributes Attributes OPTIONAL,
 *    content  ContentInfo
 * }
 * </pre>
 * The countersignatureType identifying a time stamp countersignature is the exact
 * OID 1.3.6.1.4.1.311.3.2.1 ({@link MicrosoftObjectIdentifiers#microsoftTimeStampRequest}).
 * No attributes are currently included in requests. The content is a PKCS#7 ContentInfo
 * of type data whose content is the encryptedDigest (signature) from the SignerInfo of
 * the PKCS#7 SignedData to be time stamped.
 * <p>
 * On the wire the request travels as the body of an HTTP 1.1 POST, base64 encoded,
 * with Content-Type application/octet-stream. The response is a base64 encoded PKCS#7
 * SignedData whose SignerInfo the requester copies into the original SignedData as a
 * PKCS#9 countersignature (an unsigned attribute of the original SignerInfo), merging
 * the time stamper's certificates into the original SignedData's certificate set.
 * <p>
 * See <a href="https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures">
 * Time Stamping Authenticode Signatures</a>.
 */
public class TimeStampRequest
    extends ASN1Object
{
    private final ASN1ObjectIdentifier countersignatureType;
    private final Attributes attributes;
    private final ContentInfo content;

    public static TimeStampRequest getInstance(Object obj)
    {
        if (obj instanceof TimeStampRequest)
        {
            return (TimeStampRequest)obj;
        }
        else if (obj != null)
        {
            return new TimeStampRequest(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private TimeStampRequest(ASN1Sequence seq)
    {
        if (seq.size() < 2 || seq.size() > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.countersignatureType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() == 3)
        {
            this.attributes = Attributes.getInstance(seq.getObjectAt(1));
        }
        else
        {
            this.attributes = null;
        }

        this.content = ContentInfo.getInstance(seq.getObjectAt(seq.size() - 1));
    }

    /**
     * Construct a time stamp request for the given content using the standard
     * Authenticode countersignature type OID, 1.3.6.1.4.1.311.3.2.1, and no attributes.
     *
     * @param content a ContentInfo of type data carrying the signature to be time stamped.
     */
    public TimeStampRequest(ContentInfo content)
    {
        this(MicrosoftObjectIdentifiers.microsoftTimeStampRequest, null, content);
    }

    public TimeStampRequest(ASN1ObjectIdentifier countersignatureType, Attributes attributes, ContentInfo content)
    {
        this.countersignatureType = countersignatureType;
        this.attributes = attributes;
        this.content = content;
    }

    public ASN1ObjectIdentifier getCountersignatureType()
    {
        return countersignatureType;
    }

    /**
     * Return the attributes included in the request, or null if there are none.
     */
    public Attributes getAttributes()
    {
        return attributes;
    }

    public ContentInfo getContent()
    {
        return content;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(countersignatureType);

        if (attributes != null)
        {
            v.add(attributes);
        }

        v.add(content);

        return new DERSequence(v);
    }
}
