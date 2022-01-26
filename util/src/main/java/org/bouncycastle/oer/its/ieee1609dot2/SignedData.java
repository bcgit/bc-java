package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashAlgorithm;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;

/**
 * <pre>
 *     SignedData ::= SEQUENCE {
 *         hashId HashAlgorithm,
 *         tbsData ToBeSignedData,
 *         signer SignerIdentifier,
 *         signature Signature
 *     }
 * </pre>
 */
public class SignedData
    extends ASN1Object
{
    private final HashAlgorithm hashId;
    private final ToBeSignedData tbsData;
    private final SignerIdentifier signer;
    private final Signature signature;

    public SignedData(HashAlgorithm hashId, ToBeSignedData toBeSignedData, SignerIdentifier signerIdentifier, Signature signature)
    {
        this.hashId = hashId;
        this.tbsData = toBeSignedData;
        this.signer = signerIdentifier;
        this.signature = signature;
    }

    public static SignedData getInstance(Object src)
    {
        if (src instanceof SignedData)
        {
            return (SignedData)src;
        }

        Iterator<ASN1Encodable> items = ASN1Sequence.getInstance(src).iterator();
        return new SignedData(
            HashAlgorithm.getInstance(items.next()),
            ToBeSignedData.getInstance(items.next()),
            SignerIdentifier.getInstance(items.next()),
            Signature.getInstance(items.next()));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(hashId, tbsData, signer, signature);
    }

    public HashAlgorithm getHashId()
    {
        return hashId;
    }

    public ToBeSignedData getTbsData()
    {
        return tbsData;
    }

    public SignerIdentifier getSigner()
    {
        return signer;
    }

    public Signature getSignature()
    {
        return signature;
    }

    public Builder builder()
    {
        return new Builder();
    }

    public class Builder
    {
        private HashAlgorithm hashId;
        private ToBeSignedData tbsData;
        private SignerIdentifier signer;
        private Signature signature;


        public Builder setHashId(HashAlgorithm hashId)
        {
            this.hashId = hashId;
            return this;
        }

        public Builder setTbsData(ToBeSignedData tbsData)
        {
            this.tbsData = tbsData;
            return this;
        }

        public Builder setSigner(SignerIdentifier signer)
        {
            this.signer = signer;
            return this;
        }

        public Builder setSignature(Signature signature)
        {
            this.signature = signature;
            return this;
        }

        public SignedData build()
        {
            return new SignedData(hashId, tbsData, signer, signature);
        }
    }


}