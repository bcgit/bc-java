package org.bouncycastle.asn1.cryptopro;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Arrays;

/**
 *  <pre>
 * GostR3410-TransportParameters ::= SEQUENCE {
 *        encryptionParamSet   OBJECT IDENTIFIER,
 *        ephemeralPublicKey   [0] IMPLICIT SubjectPublicKeyInfo OPTIONAL,
 *        ukm                  OCTET STRING
 * }
 *  </pre>
 */
public class GostR3410TransportParameters
    extends ASN1Object
{
    private final ASN1ObjectIdentifier encryptionParamSet;
    private final SubjectPublicKeyInfo ephemeralPublicKey;
    private final byte[] ukm;

    public GostR3410TransportParameters(ASN1ObjectIdentifier encryptionParamSet, SubjectPublicKeyInfo ephemeralPublicKey, byte[] ukm)
    {
        this.encryptionParamSet = encryptionParamSet;
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.ukm = Arrays.clone(ukm);
    }

    private GostR3410TransportParameters(ASN1Sequence seq)
    {
        if (seq.size() == 2)
        {
            this.encryptionParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.ukm = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
            this.ephemeralPublicKey = null;
        }
        else if (seq.size() == 3)
        {
            this.encryptionParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.ephemeralPublicKey = SubjectPublicKeyInfo.getInstance(
                ASN1TaggedObject.getInstance(seq.getObjectAt(1)), false);
            this.ukm = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        }
        else
        {
            throw new IllegalArgumentException("unknown sequence length: " + seq.size());
        }
    }

    public static GostR3410TransportParameters getInstance(
        Object obj)
    {
        if (obj instanceof GostR3410TransportParameters)
        {
            return (GostR3410TransportParameters)obj;
        }

        if (obj != null)
        {
            return new GostR3410TransportParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static GostR3410TransportParameters getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return new GostR3410TransportParameters(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1ObjectIdentifier getEncryptionParamSet()
    {
        return encryptionParamSet;
    }

    public SubjectPublicKeyInfo getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }

    public byte[] getUkm()
    {
        return Arrays.clone(ukm);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(encryptionParamSet);

        if (ephemeralPublicKey != null)
        {
            v.add(new DERTaggedObject(false, 0, ephemeralPublicKey));
        }

        v.add(new DEROctetString(ukm));

        return new DERSequence(v);
    }
}
