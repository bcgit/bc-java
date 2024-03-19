package org.bouncycastle.asn1.cryptopro;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers;

public class GOST3410PublicKeyAlgParameters
    extends ASN1Object
{
    private ASN1ObjectIdentifier  publicKeyParamSet;
    private ASN1ObjectIdentifier  digestParamSet;
    private ASN1ObjectIdentifier  encryptionParamSet;
    
    public static GOST3410PublicKeyAlgParameters getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GOST3410PublicKeyAlgParameters getInstance(
        Object obj)
    {
        if (obj instanceof GOST3410PublicKeyAlgParameters)
        {
            return (GOST3410PublicKeyAlgParameters)obj;
        }

        if(obj != null)
        {
            return new GOST3410PublicKeyAlgParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }
    
    public GOST3410PublicKeyAlgParameters(
        ASN1ObjectIdentifier  publicKeyParamSet,
        ASN1ObjectIdentifier  digestParamSet)
    {
        this.publicKeyParamSet = publicKeyParamSet;
        this.digestParamSet = digestParamSet;
        this.encryptionParamSet = null;
    }

    public GOST3410PublicKeyAlgParameters(
        ASN1ObjectIdentifier  publicKeyParamSet,
        ASN1ObjectIdentifier  digestParamSet,
        ASN1ObjectIdentifier  encryptionParamSet)
    {
        this.publicKeyParamSet = publicKeyParamSet;
        this.digestParamSet = digestParamSet;
        this.encryptionParamSet = encryptionParamSet;
    }

    private GOST3410PublicKeyAlgParameters(
        ASN1Sequence  seq)
    {
        this.publicKeyParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (publicKeyParamSet.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA))
        {
            if (seq.size() > 1)
            {
                digestParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
            }
        }
        else if (publicKeyParamSet.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetB)
            || publicKeyParamSet.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetC)
            || publicKeyParamSet.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetD))
        {
            if (seq.size() > 1)
            {
                throw new IllegalArgumentException("digestParamSet expected to be absent");
            }
        }
        else
        {
            if (seq.size() > 1)
            {
                digestParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
            }
        }
        
        if (seq.size() > 2)
        {
            this.encryptionParamSet = (ASN1ObjectIdentifier)seq.getObjectAt(2);
        }
    }

    public ASN1ObjectIdentifier getPublicKeyParamSet()
    {
        return publicKeyParamSet;
    }

    public ASN1ObjectIdentifier getDigestParamSet()
    {
        return digestParamSet;
    }

    public ASN1ObjectIdentifier getEncryptionParamSet()
    {
        return encryptionParamSet;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(publicKeyParamSet);

        if (digestParamSet != null)
        {
            v.add(digestParamSet);
        }
        
        if (encryptionParamSet != null)
        {
            v.add(encryptionParamSet);
        }

        return new DERSequence(v);
    }
}
