package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.EcSignature;
import org.bouncycastle.oer.its.etsi102941.basetypes.PublicKeys;
import org.bouncycastle.util.Arrays;

/**
 * InnerAtRequest ::= SEQUENCE {
 * publicKeys                    PublicKeys,
 * hmacKey                       OCTET STRING (SIZE(32)),
 * sharedAtRequest               SharedAtRequest,
 * ecSignature                   EcSignature,
 * ...
 * }
 */
public class InnerAtRequest
    extends ASN1Object
{

    private final PublicKeys publicKeys;
    private final ASN1OctetString hmacKey;
    private final SharedAtRequest sharedAtRequest;
    private final EcSignature ecSignature;

    public InnerAtRequest(
        PublicKeys publicKeys,
        ASN1OctetString hmacKey,
        SharedAtRequest sharedAtRequest,
        EcSignature ecSignature)
    {
        this.publicKeys = publicKeys;
        this.hmacKey = hmacKey;
        this.sharedAtRequest = sharedAtRequest;
        this.ecSignature = ecSignature;
    }

    private InnerAtRequest(ASN1Sequence seq)
    {
        if (seq.size() != 4)
        {
            throw new IllegalArgumentException("expected sequence size of 4");
        }

        publicKeys = PublicKeys.getInstance(seq.getObjectAt(0));
        hmacKey = ASN1OctetString.getInstance(seq.getObjectAt(1));
        sharedAtRequest = SharedAtRequest.getInstance(seq.getObjectAt(2));
        ecSignature = EcSignature.getInstance(seq.getObjectAt(3));

    }

    public static InnerAtRequest getInstance(Object o)
    {
        if (o instanceof InnerAtRequest)
        {
            return (InnerAtRequest)o;
        }

        if (o != null)
        {
            return new InnerAtRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PublicKeys getPublicKeys()
    {
        return publicKeys;
    }

    public ASN1OctetString getHmacKey()
    {
        return hmacKey;
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
        return new DERSequence(new ASN1Encodable[]{publicKeys, hmacKey, sharedAtRequest, ecSignature});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private PublicKeys publicKeys;
        private ASN1OctetString hmacKey;
        private SharedAtRequest sharedAtRequest;
        private EcSignature ecSignature;

        public Builder setPublicKeys(PublicKeys publicKeys)
        {
            this.publicKeys = publicKeys;
            return this;
        }

        public Builder setHmacKey(ASN1OctetString hmacKey)
        {
            this.hmacKey = hmacKey;
            return this;
        }

        public Builder setHmacKey(byte[] hmacKey)
        {
            this.hmacKey = new DEROctetString(Arrays.clone(hmacKey));
            return this;
        }

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

        public InnerAtRequest createInnerAtRequest()
        {
            return new InnerAtRequest(publicKeys, hmacKey, sharedAtRequest, ecSignature);
        }
    }

}
