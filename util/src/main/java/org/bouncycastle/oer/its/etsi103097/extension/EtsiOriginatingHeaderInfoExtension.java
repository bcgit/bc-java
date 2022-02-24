/**
 * EtsiTs103097ExtensionModule
 * {itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) extension(2) version1(1)}
 */
package org.bouncycastle.oer.its.etsi103097.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Ieee1609Dot2HeaderInfoContributedExtensions
 * IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= {
 * {EtsiOriginatingHeaderInfoExtension IDENTIFIED BY etsiHeaderInfoContributorId},
 * ...
 * }
 */
public class EtsiOriginatingHeaderInfoExtension
    extends Extension
{
    public EtsiOriginatingHeaderInfoExtension(ExtId id, ASN1Encodable content)
    {
        super(id, content);
    }

    private EtsiOriginatingHeaderInfoExtension(ASN1Sequence sequence)
    {
        super(sequence);
    }

    public static EtsiOriginatingHeaderInfoExtension getInstance(Object o)
    {
        if (o instanceof EtsiOriginatingHeaderInfoExtension)
        {
            return (EtsiOriginatingHeaderInfoExtension)o;
        }

        if (o != null)
        {
            return new EtsiOriginatingHeaderInfoExtension(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public EtsiTs102941CrlRequest getEtsiTs102941CrlRequest()
    {
        return EtsiTs102941CrlRequest.getInstance(getContent());
    }

    public EtsiTs102941DeltaCtlRequest getEtsiTs102941DeltaCtlRequest()
    {
        return EtsiTs102941DeltaCtlRequest.getInstance(getContent());
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private ExtId id;
        private ASN1Encodable encodable;

        public Builder setId(ExtId id)
        {
            this.id = id;
            return this;
        }

        public Builder setEncodable(ASN1Encodable encodable)
        {
            this.encodable = encodable;
            return this;
        }

        public Builder setEtsiTs102941CrlRequest(EtsiTs102941CrlRequest value)
        {
            this.id = etsiTs102941CrlRequestId;
            this.encodable = value;
            return this;
        }

        public Builder setEtsiTs102941DeltaCtlRequest(EtsiTs102941DeltaCtlRequest value)
        {
            this.id = etsiTs102941DeltaCtlRequestId;
            this.encodable = value;
            return this;
        }

        public EtsiOriginatingHeaderInfoExtension createEtsiOriginatingHeaderInfoExtension()
        {
            return new EtsiOriginatingHeaderInfoExtension(id, encodable);
        }


    }


}
