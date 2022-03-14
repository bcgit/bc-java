package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Certificate;
import org.bouncycastle.util.Arrays;


/**
 * InnerEcResponse ::= SEQUENCE {
 * requestHash                           OCTET STRING (SIZE(16)),
 * responseCode                          EnrolmentResponseCode,
 * certificate                           EtsiTs103097Certificate OPTIONAL,
 * ...
 * }
 * (WITH COMPONENTS { responseCode (ok), certificate PRESENT }
 * | WITH COMPONENTS { responseCode (ALL EXCEPT ok), certificate ABSENT }
 * )
 */
public class InnerEcResponse
    extends ASN1Object
{
    private final ASN1OctetString requestHash;
    private final EnrolmentResponseCode responseCode;
    private final EtsiTs103097Certificate certificate;

    public InnerEcResponse(ASN1OctetString requestHash, EnrolmentResponseCode responseCode, EtsiTs103097Certificate certificate)
    {
        this.requestHash = requestHash;
        this.responseCode = responseCode;
        this.certificate = certificate;
    }

    private InnerEcResponse(ASN1Sequence sequence)
    {
        if (sequence.size() != 3)
        {
            throw new IllegalArgumentException("expected sequence size of 3");
        }
        requestHash = ASN1OctetString.getInstance(sequence.getObjectAt(0));
        responseCode = EnrolmentResponseCode.getInstance(sequence.getObjectAt(1));
        certificate = OEROptional.getValue(EtsiTs103097Certificate.class, sequence.getObjectAt(2));
    }

    public static InnerEcResponse getInstance(Object o)
    {
        if (o instanceof InnerEcResponse)
        {
            return (InnerEcResponse)o;
        }

        if (o != null)
        {
            return new InnerEcResponse(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public ASN1OctetString getRequestHash()
    {
        return requestHash;
    }

    public EnrolmentResponseCode getResponseCode()
    {
        return responseCode;
    }

    public EtsiTs103097Certificate getCertificate()
    {
        return certificate;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{
            requestHash, responseCode, OEROptional.getInstance(certificate)
        });
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private ASN1OctetString requestHash;
        private EnrolmentResponseCode responseCode;
        private EtsiTs103097Certificate certificate;

        public Builder setRequestHash(ASN1OctetString requestHash)
        {
            this.requestHash = requestHash;
            return this;
        }

        public Builder setRequestHash(byte[] requestHash)
        {
            this.requestHash = new DEROctetString(Arrays.clone(requestHash));
            return this;
        }


        public Builder setResponseCode(EnrolmentResponseCode responseCode)
        {
            this.responseCode = responseCode;
            return this;
        }

        public Builder setCertificate(EtsiTs103097Certificate certificate)
        {
            this.certificate = certificate;
            return this;
        }

        public InnerEcResponse createInnerEcResponse()
        {
            return new InnerEcResponse(requestHash, responseCode, certificate);
        }

    }
}
