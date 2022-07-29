package org.bouncycastle.oer.its.etsi103097.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Extension {EXT-TYPE : ExtensionTypes} ::= SEQUENCE {
 * id      EXT-TYPE.&amp;extId({ExtensionTypes}),
 * content EXT-TYPE.&amp;ExtContent({ExtensionTypes}{&#64;.id})
 * }
 * <p>
 * Where:
 * EtsiTs103097HeaderInfoExtensionId ::= ExtId
 * etsiTs102941CrlRequestId      EtsiTs103097HeaderInfoExtensionId ::= 1 --'01'H
 * etsiTs102941DeltaCtlRequestId EtsiTs103097HeaderInfoExtensionId ::= 2 --'02'H
 * <p>
 * EtsiTs103097HeaderInfoExtensions EXT-TYPE ::= {
 * { EtsiTs102941CrlRequest       IDENTIFIED BY etsiTs102941CrlRequestId } |
 * { EtsiTs102941DeltaCtlRequest  IDENTIFIED BY etsiTs102941DeltaCtlRequestId },
 * ...
 * }
 */
public class Extension
    extends ASN1Object
{

    /**
     * etsiTs102941CrlRequestId EtsiTs103097HeaderInfoExtensionId ::= 1
     */
    public static final ExtId etsiTs102941CrlRequestId = new ExtId(1);

    /**
     * etsiTs102941DeltaCtlRequestId EtsiTs103097HeaderInfoExtensionId ::= 2
     */
    public static final ExtId etsiTs102941DeltaCtlRequestId = new ExtId(2);

    private final ExtId id;
    private final ASN1Encodable content;

    protected Extension(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        id = ExtId.getInstance(sequence.getObjectAt(0));

        if (id.equals(etsiTs102941CrlRequestId))
        {
            content = EtsiTs102941CrlRequest.getInstance(sequence.getObjectAt(1));
        }
        else if (id.equals(etsiTs102941DeltaCtlRequestId))
        {
            content = EtsiTs102941DeltaCtlRequest.getInstance(sequence.getObjectAt(1));
        }
        else
        {
            throw new IllegalArgumentException("id not 1 (EtsiTs102941CrlRequest) or 2 (EtsiTs102941DeltaCtlRequest)");
        }
    }

    public Extension(ExtId id, ASN1Encodable content)
    {
        this.id = id;

        if (id.getExtId().intValue() != 1 && id.getExtId().intValue() != 2)
        {
            throw new IllegalArgumentException("id not 1 (EtsiTs102941CrlRequest) or 2 (EtsiTs102941DeltaCtlRequest)");
        }
        this.content = content;
    }

    public static Extension etsiTs102941CrlRequest(EtsiTs102941CrlRequest request)
    {
        return new Extension(etsiTs102941CrlRequestId, request);
    }

    public static Extension etsiTs102941DeltaCtlRequest(EtsiTs102941DeltaCtlRequest request)
    {
        return new Extension(etsiTs102941DeltaCtlRequestId, request);
    }

    public static Extension getInstance(Object o)
    {
        if (o instanceof Extension)
        {
            return (Extension)o;
        }

        if (o != null)
        {
            return new Extension(ASN1Sequence.getInstance(o));
        }

        return null;

    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{id, content});
    }

    public ExtId getId()
    {
        return id;
    }

    public ASN1Encodable getContent()
    {
        return content;
    }

}
