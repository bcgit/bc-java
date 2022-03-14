package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.etsi102941.basetypes.CertificateSubjectAttributes;
import org.bouncycastle.util.Arrays;

/**
 * AuthorizationValidationResponse ::= SEQUENCE {
 * requestHash                   OCTET STRING (SIZE(16)),
 * responseCode                  AuthorizationValidationResponseCode,
 * confirmedSubjectAttributes    CertificateSubjectAttributes (WITH COMPONENTS{..., certIssuePermissions ABSENT}) OPTIONAL,
 * ...
 * }
 * (WITH COMPONENTS { responseCode (ok), confirmedSubjectAttributes PRESENT }
 * | WITH COMPONENTS { responseCode (ALL EXCEPT ok), confirmedSubjectAttributes ABSENT }
 * )
 */
public class AuthorizationValidationResponse
    extends ASN1Object
{
    private final ASN1OctetString requestHash;
    private final AuthorizationValidationResponseCode responseCode;
    private final CertificateSubjectAttributes confirmedSubjectAttributes;


    public AuthorizationValidationResponse(
        ASN1OctetString requestHash,
        AuthorizationValidationResponseCode responseCode,
        CertificateSubjectAttributes confirmedSubjectAttributes)
    {
        this.requestHash = requestHash;
        this.responseCode = responseCode;
        this.confirmedSubjectAttributes = confirmedSubjectAttributes;
    }

    private AuthorizationValidationResponse(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("expected sequence size of 3");
        }
        requestHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        responseCode = AuthorizationValidationResponseCode.getInstance(seq.getObjectAt(1));
        confirmedSubjectAttributes = OEROptional.getValue(CertificateSubjectAttributes.class, seq.getObjectAt(2));
    }

    public static AuthorizationValidationResponse getInstance(Object o)
    {
        if (o instanceof AuthorizationValidationResponse)
        {
            return (AuthorizationValidationResponse)o;
        }

        if (o != null)
        {
            return new AuthorizationValidationResponse(ASN1Sequence.getInstance(o));
        }
        return null;
    }


    public ASN1OctetString getRequestHash()
    {
        return requestHash;
    }

    public AuthorizationValidationResponseCode getResponseCode()
    {
        return responseCode;
    }

    public CertificateSubjectAttributes getConfirmedSubjectAttributes()
    {
        return confirmedSubjectAttributes;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{requestHash, responseCode, OEROptional.getInstance(confirmedSubjectAttributes)});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private ASN1OctetString requestHash;
        private AuthorizationValidationResponseCode responseCode;
        private CertificateSubjectAttributes confirmedSubjectAttributes;

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

        public Builder setResponseCode(AuthorizationValidationResponseCode responseCode)
        {
            this.responseCode = responseCode;
            return this;
        }

        public Builder setConfirmedSubjectAttributes(CertificateSubjectAttributes confirmedSubjectAttributes)
        {
            this.confirmedSubjectAttributes = confirmedSubjectAttributes;
            return this;
        }

        public AuthorizationValidationResponse createAuthorizationValidationResponse()
        {
            return new AuthorizationValidationResponse(requestHash, responseCode, confirmedSubjectAttributes);
        }

    }
}
