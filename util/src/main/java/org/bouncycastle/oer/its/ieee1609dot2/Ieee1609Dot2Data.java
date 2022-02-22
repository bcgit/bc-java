package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data_Encrypted;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data_Encrypted_Unicast;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data_Signed;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data_SignedAndEncrypted;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data_SignedExternalPayload;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data_Unsecured;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

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
    private final UINT8 protocolVersion;
    private final Ieee1609Dot2Content content;

    public Ieee1609Dot2Data(UINT8 protocolVersion, Ieee1609Dot2Content content)
    {
        this.protocolVersion = protocolVersion;
        this.content = content;
    }

    protected Ieee1609Dot2Data(ASN1Sequence src)
    {
        if (src.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        Iterator<ASN1Encodable> items = ASN1Sequence.getInstance(src).iterator();
        this.protocolVersion = UINT8.getInstance(items.next());
        this.content = Ieee1609Dot2Content.getInstance(items.next());
    }

    public static Ieee1609Dot2Data getInstance(Object src)
    {
        if (src instanceof Ieee1609Dot2Data)
        {
            return (Ieee1609Dot2Data)src;
        }

        if (src != null)
        {
            return new Ieee1609Dot2Data(ASN1Sequence.getInstance(src));
        }

        return null;
    }


    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(protocolVersion, content);
    }

    public UINT8 getProtocolVersion()
    {
        return protocolVersion;
    }

    public Ieee1609Dot2Content getContent()
    {
        return content;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private UINT8 protocolVersion;
        private Ieee1609Dot2Content content;

        public Builder setProtocolVersion(UINT8 protocolVersion)
        {
            this.protocolVersion = protocolVersion;
            return this;
        }

        public Builder setContent(Ieee1609Dot2Content content)
        {
            this.content = content;
            return this;
        }

        public Ieee1609Dot2Data createIeee1609Dot2Data()
        {
            return new Ieee1609Dot2Data(protocolVersion, content);
        }

        public CounterSignature createCounterSignature()
        {
            return new CounterSignature(protocolVersion, content);
        }

        public EtsiTs103097Data createEtsiTs103097Data()
        {
            return new EtsiTs103097Data(protocolVersion, content);
        }

        public EtsiTs103097Data_Unsecured createEtsiTs103097Data_Unsecured()
        {
            return new EtsiTs103097Data_Unsecured(content);
        }

        public EtsiTs103097Data_Signed createEtsiTs103097Data_Signed()
        {
            return new EtsiTs103097Data_Signed(content);
        }

        public EtsiTs103097Data_SignedExternalPayload createEtsiTs103097Data_SignedExternalPayload()
        {
            return new EtsiTs103097Data_SignedExternalPayload(content);
        }

        public EtsiTs103097Data_Encrypted createEtsiTs103097Data_Encrypted()
        {
            return new EtsiTs103097Data_Encrypted(content);
        }

        public EtsiTs103097Data_SignedAndEncrypted createEtsiTs103097Data_SignedAndEncrypted()
        {
            return new EtsiTs103097Data_SignedAndEncrypted(content);
        }

        public EtsiTs103097Data_Encrypted_Unicast createEtsiTs103097Data_Encrypted_Unicast()
        {
            return new EtsiTs103097Data_Encrypted_Unicast(content);
        }
    }

}
