package org.bouncycastle.asn1.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * <pre>
 * ObjectStoreIntegrityCheck ::= CHOICE {
 *     PbeMacIntegrityCheck
 * }
 * </pre>
 */
public class ObjectStoreIntegrityCheck
    extends ASN1Object
    implements ASN1Choice
{
    public static final int PBKD_MAC_CHECK = 0;

    private final int type;
    private final ASN1Object integrityCheck;

    public ObjectStoreIntegrityCheck(PbkdMacIntegrityCheck macIntegrityCheck)
    {
        this((ASN1Encodable)macIntegrityCheck);
    }

    private ObjectStoreIntegrityCheck(ASN1Encodable obj)
    {
        if (obj instanceof ASN1Sequence || obj instanceof  PbkdMacIntegrityCheck)
        {
            this.type = PBKD_MAC_CHECK;
            this.integrityCheck = PbkdMacIntegrityCheck.getInstance(obj);
        }
        else
        {
            throw new IllegalArgumentException("Unknown check object in integrity check.");
        }
    }

    public static ObjectStoreIntegrityCheck getInstance(Object o)
    {
        if (o instanceof ObjectStoreIntegrityCheck)
        {
            return (ObjectStoreIntegrityCheck)o;
        }
        else if (o instanceof byte[])
        {
            try
            {
                return new ObjectStoreIntegrityCheck(ASN1Primitive.fromByteArray((byte[])o));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("Unable to parse integrity check details.");
            }
        }
        else if (o != null)
        {
            return new ObjectStoreIntegrityCheck((ASN1Encodable)(o));
        }

        return null;
    }


    public int getType()
    {
        return type;
    }

    public ASN1Object getIntegrityCheck()
    {
        return integrityCheck;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return integrityCheck.toASN1Primitive();
    }
}
