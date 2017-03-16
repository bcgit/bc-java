package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * ObjectStore ::= SEQUENCE {
 *     CHOICE {
 *          encryptedObjectStoreData EncryptedObjectStoreData,
 *          objectStoreData ObjectStoreData
 *     }
 *     integrityCheck ObjectStoreIntegrityCheck
 * }
 * </pre>
 */
public class ObjectStore
    extends ASN1Object
{
    private final ASN1Encodable storeData;
    private final ObjectStoreIntegrityCheck integrityCheck;

    public ObjectStore(ObjectStoreData objectStoreData, ObjectStoreIntegrityCheck integrityCheck)
    {
        this.storeData = objectStoreData;
        this.integrityCheck = integrityCheck;
    }


    public ObjectStore(EncryptedObjectStoreData encryptedObjectStoreData, ObjectStoreIntegrityCheck integrityCheck)
    {
        this.storeData = encryptedObjectStoreData;
        this.integrityCheck = integrityCheck;
    }

    private ObjectStore(ASN1Sequence seq)
    {
        ASN1Encodable sData = seq.getObjectAt(0);
        if (sData instanceof EncryptedObjectStoreData)
        {
            this.storeData = sData;
        }
        else if (sData instanceof ObjectStoreData)
        {
            this.storeData = sData;
        }
        else
        {
            ASN1Sequence seqData = ASN1Sequence.getInstance(sData);

            if (seqData.size() == 2)
            {
                this.storeData = EncryptedObjectStoreData.getInstance(seqData);
            }
            else
            {
                this.storeData = ObjectStoreData.getInstance(seqData);
            }
        }

        this.integrityCheck = ObjectStoreIntegrityCheck.getInstance(seq.getObjectAt(1));
    }

    public static ObjectStore getInstance(Object o)
    {
        if (o instanceof ObjectStore)
        {
            return (ObjectStore)o;
        }
        else if (o != null)
        {
            return new ObjectStore(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ObjectStoreIntegrityCheck getIntegrityCheck()
    {
        return integrityCheck;
    }

    public ASN1Encodable getStoreData()
    {
        return storeData;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(storeData);
        v.add(integrityCheck);

        return new DERSequence(v);
    }
}
