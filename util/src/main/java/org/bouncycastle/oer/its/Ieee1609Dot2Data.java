package org.bouncycastle.oer.its;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * <pre>
 *     Ieee1609Dot2Data ::= SEQUENCE {
 *         protocolVersion Uint8(3),
 *         content Ieee1609Dot2Content
 *     }
 * </pre>
 */
public class Ieee1609Dot2Data
    extends ASN1Object
{
    private final Uint8 protocolVersion;
    private final Ieee1609Dot2Content content;

    public Ieee1609Dot2Data(Uint8 protocolVersion, Ieee1609Dot2Content content)
    {
        this.protocolVersion = protocolVersion;
        this.content = content;
    }

    public static Ieee1609Dot2Data getInstance(Object src)
    {
        if (src instanceof Ieee1609Dot2Data)
        {
            return (Ieee1609Dot2Data)src;
        }

        Iterator<ASN1Encodable> items = ASN1Sequence.getInstance(src).iterator();
        return new Ieee1609Dot2Data(Uint8.getInstance(items.next()), Ieee1609Dot2Content.getInstance(items.next()));
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(protocolVersion, content);
    }

    public Uint8 getProtocolVersion()
    {
        return protocolVersion;
    }

    public Ieee1609Dot2Content getContent()
    {
        return content;
    }

    public static class Builder
    {
        private Uint8 protocolVersion;
        private Ieee1609Dot2Content content;

        public Builder setProtocolVersion(Uint8 protocolVersion)
        {
            this.protocolVersion = protocolVersion;
            return this;
        }

        public Builder setContent(Ieee1609Dot2Content content)
        {
            this.content = content;
            return this;
        }

        public Ieee1609Dot2Data build()
        {
            return new Ieee1609Dot2Data(protocolVersion, content);
        }

    }

}
