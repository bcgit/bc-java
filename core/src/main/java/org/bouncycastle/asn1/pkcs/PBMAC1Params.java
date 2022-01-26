package org.bouncycastle.asn1.pkcs;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


/**
 * From https://datatracker.ietf.org/doc/html/rfc8018
 *
 * <pre>
 * PBMAC1-params ::= SEQUENCE {
 *     keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
 *     messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}} }
 * </pre>
 */
public class PBMAC1Params
    extends ASN1Object
    implements PKCSObjectIdentifiers
{
    private AlgorithmIdentifier func;
    private AlgorithmIdentifier scheme;

    public static PBMAC1Params getInstance(
        Object  obj)
    {
        if (obj instanceof PBMAC1Params)
        {
            return (PBMAC1Params)obj;
        }
        if (obj != null)
        {
            return new PBMAC1Params(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public PBMAC1Params(AlgorithmIdentifier keyDevFunc, AlgorithmIdentifier encScheme)
    {
        this.func = keyDevFunc;
        this.scheme = encScheme;
    }

    private PBMAC1Params(
        ASN1Sequence  obj)
    {
        Enumeration e = obj.getObjects();
        ASN1Sequence  funcSeq = ASN1Sequence.getInstance(((ASN1Encodable)e.nextElement()).toASN1Primitive());

        if (funcSeq.getObjectAt(0).equals(id_PBKDF2))
        {
            func = new AlgorithmIdentifier(id_PBKDF2, PBKDF2Params.getInstance(funcSeq.getObjectAt(1)));
        }
        else
        {
            func = AlgorithmIdentifier.getInstance(funcSeq);
        }

        scheme = AlgorithmIdentifier.getInstance(e.nextElement());
    }

    public AlgorithmIdentifier getKeyDerivationFunc()
    {
        return func;
    }

    public AlgorithmIdentifier getMessageAuthScheme()
    {
        return scheme;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(func);
        v.add(scheme);

        return new DERSequence(v);
    }
}
