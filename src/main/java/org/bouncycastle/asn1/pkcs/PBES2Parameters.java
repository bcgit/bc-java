package org.bouncycastle.asn1.pkcs;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class PBES2Parameters
    extends ASN1Object
    implements PKCSObjectIdentifiers
{
    private KeyDerivationFunc   func;
    private EncryptionScheme    scheme;

    public static PBES2Parameters getInstance(
        Object  obj)
    {
        if (obj== null || obj instanceof PBES2Parameters)
        {
            return (PBES2Parameters)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new PBES2Parameters((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public PBES2Parameters(
        ASN1Sequence  obj)
    {
        Enumeration e = obj.getObjects();
        ASN1Sequence  funcSeq = ASN1Sequence.getInstance(((ASN1Encodable)e.nextElement()).toASN1Primitive());

        if (funcSeq.getObjectAt(0).equals(id_PBKDF2))
        {
            func = new KeyDerivationFunc(id_PBKDF2, PBKDF2Params.getInstance(funcSeq.getObjectAt(1)));
        }
        else
        {
            func = new KeyDerivationFunc(funcSeq);
        }

        scheme = (EncryptionScheme)EncryptionScheme.getInstance(e.nextElement());
    }

    public KeyDerivationFunc getKeyDerivationFunc()
    {
        return func;
    }

    public EncryptionScheme getEncryptionScheme()
    {
        return scheme;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(func);
        v.add(scheme);

        return new DERSequence(v);
    }
}
