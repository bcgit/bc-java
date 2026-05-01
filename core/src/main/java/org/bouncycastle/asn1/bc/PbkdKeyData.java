package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Carrier for the contents of a {@link javax.crypto.interfaces.PBEKey} stored
 * in a BCFKS keystore.
 * <pre>
 *     PbkdKeyData ::= SEQUENCE {
 *         keyAlgorithm   UTF8String,
 *         password       OCTET STRING,
 *         salt           [0] IMPLICIT OCTET STRING OPTIONAL,
 *         iterationCount [1] IMPLICIT INTEGER OPTIONAL,
 *         encoded        [2] IMPLICIT OCTET STRING OPTIONAL
 *     }
 * </pre>
 */
public class PbkdKeyData
    extends ASN1Object
{
    private final ASN1UTF8String keyAlgorithm;
    private final ASN1OctetString password;
    private final ASN1OctetString salt;
    private final ASN1Integer iterationCount;
    private final ASN1OctetString encoded;

    public PbkdKeyData(String keyAlgorithm, byte[] password, byte[] salt, int iterationCount, byte[] encoded)
    {
        this.keyAlgorithm = new DERUTF8String(keyAlgorithm);
        this.password = new DEROctetString(Arrays.clone(password));
        this.salt = (salt != null) ? new DEROctetString(Arrays.clone(salt)) : null;
        this.iterationCount = (iterationCount > 0) ? new ASN1Integer(iterationCount) : null;
        this.encoded = (encoded != null) ? new DEROctetString(Arrays.clone(encoded)) : null;
    }

    private PbkdKeyData(ASN1Sequence seq)
    {
        this.keyAlgorithm = ASN1UTF8String.getInstance(seq.getObjectAt(0));
        this.password = ASN1OctetString.getInstance(seq.getObjectAt(1));

        ASN1OctetString salt = null;
        ASN1Integer iterationCount = null;
        ASN1OctetString encoded = null;

        for (int i = 2; i != seq.size(); i++)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(i));

            switch (tagged.getTagNo())
            {
            case 0:
                salt = ASN1OctetString.getInstance(tagged, false);
                break;
            case 1:
                iterationCount = ASN1Integer.getInstance(tagged, false);
                break;
            case 2:
                encoded = ASN1OctetString.getInstance(tagged, false);
                break;
            default:
                throw new IllegalArgumentException("unknown tag in PbkdKeyData: " + tagged.getTagNo());
            }
        }

        this.salt = salt;
        this.iterationCount = iterationCount;
        this.encoded = encoded;
    }

    public static PbkdKeyData getInstance(Object o)
    {
        if (o instanceof PbkdKeyData)
        {
            return (PbkdKeyData)o;
        }
        else if (o != null)
        {
            return new PbkdKeyData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public String getKeyAlgorithm()
    {
        return keyAlgorithm.getString();
    }

    public byte[] getPassword()
    {
        return Arrays.clone(password.getOctets());
    }

    public byte[] getSalt()
    {
        return (salt != null) ? Arrays.clone(salt.getOctets()) : null;
    }

    public int getIterationCount()
    {
        return (iterationCount != null) ? BigIntegers.intValueExact(iterationCount.getValue()) : 0;
    }

    public byte[] getKeyEncoding()
    {
        return (encoded != null) ? Arrays.clone(encoded.getOctets()) : null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(5);
        v.add(keyAlgorithm);
        v.add(password);
        if (salt != null)
        {
            v.add(new DERTaggedObject(false, 0, salt));
        }
        if (iterationCount != null)
        {
            v.add(new DERTaggedObject(false, 1, iterationCount));
        }
        if (encoded != null)
        {
            v.add(new DERTaggedObject(false, 2, encoded));
        }
        return new DERSequence(v);
    }
}
