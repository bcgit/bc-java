package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.EcSignature;

/**
 * AuthorizationValidationRequest ::= SEQUENCE {
 * sharedAtRequest               SharedAtRequest,
 * ecSignature                   EcSignature,
 * ...
 * }
 */
public class AuthorizationValidationRequest
    extends ASN1Object
{
    private final SharedAtRequest sharedAtRequest;
    private final EcSignature ecSignature;

    public AuthorizationValidationRequest(SharedAtRequest sharedAtRequest, EcSignature ecSignature)
    {
        this.sharedAtRequest = sharedAtRequest;
        this.ecSignature = ecSignature;
    }

    private AuthorizationValidationRequest(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        sharedAtRequest = SharedAtRequest.getInstance(seq.getObjectAt(0));
        ecSignature = EcSignature.getInstance(seq.getObjectAt(1));
    }

    public static AuthorizationValidationRequest getInstance(Object o)
    {
        if (o instanceof AuthorizationValidationRequest)
        {
            return (AuthorizationValidationRequest)o;
        }

        if (o != null)
        {
            return new AuthorizationValidationRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public SharedAtRequest getSharedAtRequest()
    {
        return sharedAtRequest;
    }

    public EcSignature getEcSignature()
    {
        return ecSignature;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{sharedAtRequest, ecSignature});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private SharedAtRequest sharedAtRequest;
        private EcSignature ecSignature;

        public Builder setSharedAtRequest(SharedAtRequest sharedAtRequest)
        {
            this.sharedAtRequest = sharedAtRequest;
            return this;
        }

        public Builder setEcSignature(EcSignature ecSignature)
        {
            this.ecSignature = ecSignature;
            return this;
        }

        public AuthorizationValidationRequest createAuthorizationValidationRequest()
        {
            return new AuthorizationValidationRequest(sharedAtRequest, ecSignature);
        }

    }

}
