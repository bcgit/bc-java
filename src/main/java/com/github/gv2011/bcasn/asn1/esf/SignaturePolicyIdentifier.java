package com.github.gv2011.bcasn.asn1.esf;

import com.github.gv2011.bcasn.asn1.ASN1Null;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.BERTags;
import com.github.gv2011.bcasn.asn1.DERNull;

public class SignaturePolicyIdentifier
    extends ASN1Object
{
    private SignaturePolicyId   signaturePolicyId;
    private boolean             isSignaturePolicyImplied;

    public static SignaturePolicyIdentifier getInstance(
        Object  obj)
    {
        if (obj instanceof SignaturePolicyIdentifier)
        {
            return (SignaturePolicyIdentifier)obj;
        }
        else if (obj instanceof ASN1Null || hasEncodedTagValue(obj, BERTags.NULL))
        {
            return new SignaturePolicyIdentifier();
        }
        else if (obj != null)
        {
            return new SignaturePolicyIdentifier(SignaturePolicyId.getInstance(obj));
        }

        return null;
    }

    public SignaturePolicyIdentifier()
    {
        this.isSignaturePolicyImplied = true;
    }

    public SignaturePolicyIdentifier(
        SignaturePolicyId signaturePolicyId)
    {
        this.signaturePolicyId = signaturePolicyId;
        this.isSignaturePolicyImplied = false;
    }

    public SignaturePolicyId getSignaturePolicyId()
    {
        return signaturePolicyId;
    }

    public boolean isSignaturePolicyImplied()
    {
        return isSignaturePolicyImplied;
    }

    /**
     * <pre>
     * SignaturePolicyIdentifier ::= CHOICE{
     *     SignaturePolicyId         SignaturePolicyId,
     *     SignaturePolicyImplied    SignaturePolicyImplied }
     *
     * SignaturePolicyImplied ::= NULL
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (isSignaturePolicyImplied)
        {
            return DERNull.INSTANCE;
        }
        else
        {
            return signaturePolicyId.toASN1Primitive();
        }
    }
}
