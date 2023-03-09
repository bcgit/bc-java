package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *   KEMRecipientInfo ::= SEQUENCE {
 *     version CMSVersion,  -- always set to 0
 *     rid RecipientIdentifier,
 *     kem KEMAlgorithmIdentifier,
 *     kemct OCTET STRING,
 *     kdf KeyDerivationAlgorithmIdentifier,
 *     kekLength INTEGER (1..MAX),
 *     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
 *     wrap KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey EncryptedKey }
 */
public class KEMRecipientInfo
    extends ASN1Object
{
    private final ASN1Integer cmsVersion;
    private final RecipientIdentifier rid;
    private final AlgorithmIdentifier kem;
    private final ASN1OctetString kemct;
    private final AlgorithmIdentifier kdf;
    private final ASN1Integer kekLength;
    private final ASN1OctetString ukm;
    private final AlgorithmIdentifier wrap;
    private final ASN1OctetString encryptedKey;

    public KEMRecipientInfo(RecipientIdentifier rid, AlgorithmIdentifier kem, ASN1OctetString kemct,
                            AlgorithmIdentifier kdf, ASN1Integer kekLength, ASN1OctetString ukm, AlgorithmIdentifier wrap, ASN1OctetString encryptedKey)
    {
        if (kem == null)
        {
            throw new NullPointerException("kem cannot be null");
        }
        if (wrap == null)
        {
            throw new NullPointerException("wrap cannot be null");
        }
        this.cmsVersion = new ASN1Integer(0);
        this.rid = rid;
        this.kem = kem;
        this.kemct = kemct;
        this.kdf = kdf;
        this.kekLength = kekLength;
        this.ukm = ukm;
        this.wrap = wrap;
        this.encryptedKey = encryptedKey;
    }

    public static KEMRecipientInfo getInstance(Object o)
    {
        if (o instanceof KEMRecipientInfo)
        {
            return (KEMRecipientInfo)o;
        }
        else if (o != null)
        {
            return new KEMRecipientInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private KEMRecipientInfo(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("sequence must consist of 3 elements");
        }

        cmsVersion = ASN1Integer.getInstance(seq.getObjectAt(0));
        rid = RecipientIdentifier.getInstance(seq.getObjectAt(1));
        kem = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
        kemct = ASN1OctetString.getInstance(seq.getObjectAt(3));
        kdf = AlgorithmIdentifier.getInstance(seq.getObjectAt(4));
        kekLength = ASN1Integer.getInstance(seq.getObjectAt(5));

        int elt = 6;
        if (seq.getObjectAt(6) instanceof ASN1TaggedObject)
        {
            ukm = ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(elt++)), true);
        }
        else
        {
            ukm = null;
        }
        wrap = AlgorithmIdentifier.getInstance(seq.getObjectAt(elt++));
        encryptedKey = ASN1OctetString.getInstance(seq.getObjectAt(elt++));
    }

    public RecipientIdentifier getRecipientIdentifier()
    {
        return rid;
    }

    public AlgorithmIdentifier getKem()
    {
        return kem;
    }

    public ASN1OctetString getKemct()
    {
        return kemct;
    }

    public AlgorithmIdentifier getKdf()
    {
        return kdf;
    }

    public AlgorithmIdentifier getWrap()
    {
        return wrap;
    }

    public byte[] getUkm()
     {
         if (ukm == null)
         {
             return null;
         }

         return ukm.getOctets();
     }

    public ASN1OctetString getEncryptedKey()
    {
        return encryptedKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(cmsVersion);
        v.add(rid);
        v.add(kem);
        v.add(kemct);
        v.add(kdf);
        v.add(kekLength);
        if (ukm != null)
        {
            v.add(new DERTaggedObject(true, 0, ukm));
        }
        v.add(wrap);
        v.add(encryptedKey);
        
        return new DERSequence(v);
    }
}
