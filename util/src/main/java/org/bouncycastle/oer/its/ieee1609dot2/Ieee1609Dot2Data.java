package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.etsi102941.InnerEcRequestSignedForPop;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncrypted;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncryptedUnicast;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSignedAndEncrypted;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSignedAndEncryptedUnicast;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSignedExternalPayload;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataUnsecured;
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


        public EtsiTs103097DataSigned createEtsiTs103097DataSigned()
        {
            return new EtsiTs103097DataSigned(content);
        }

        public EtsiTs103097DataSignedExternalPayload createEtsiTs103097DataSignedExternalPayload()
        {
            return new EtsiTs103097DataSignedExternalPayload(content);
        }

        public EtsiTs103097DataEncrypted createEtsiTs103097DataEncrypted()
        {
            return new EtsiTs103097DataEncrypted(content);
        }

        public EtsiTs103097DataSignedAndEncrypted createEtsiTs103097DataSignedAndEncrypted()
        {
            return new EtsiTs103097DataSignedAndEncrypted(content);
        }

        public EtsiTs103097DataEncryptedUnicast createEtsiTs103097DataEncryptedUnicast()
        {
            return new EtsiTs103097DataEncryptedUnicast(content);
        }

        public EtsiTs103097DataSignedAndEncryptedUnicast createEtsiTs103097DataSignedAndEncryptedUnicast()
        {
            return new EtsiTs103097DataSignedAndEncryptedUnicast(content);
        }

        public EtsiTs103097DataUnsecured createEtsiTs103097DataUnsecured()
        {
            return new EtsiTs103097DataUnsecured(content);
        }

        public InnerEcRequestSignedForPop createInnerEcRequestSignedForPop()
        {
            return new InnerEcRequestSignedForPop(content);
        }

    }

}
