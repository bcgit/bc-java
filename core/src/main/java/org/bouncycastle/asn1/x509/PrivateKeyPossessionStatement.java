package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;

/**
 * <pre>
 * PrivateKeyPossessionStatement ::= SEQUENCE {
 *       signer  IssuerAndSerialNumber,
 *       cert    Certificate OPTIONAL }
 * </pre>
 */
public class PrivateKeyPossessionStatement
    extends ASN1Object
{
    private final IssuerAndSerialNumber signer;
    private final Certificate cert;

    public static PrivateKeyPossessionStatement getInstance(Object obj)
    {
        if (obj instanceof PrivateKeyPossessionStatement)
        {
            return (PrivateKeyPossessionStatement)obj;
        }

        if (obj != null)
        {
            return new PrivateKeyPossessionStatement(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private PrivateKeyPossessionStatement(ASN1Sequence seq)
    {
        if (seq.size() == 1)
        {
             this.signer = IssuerAndSerialNumber.getInstance(seq.getObjectAt(0));
             this.cert = null;
        }
        else if (seq.size() == 2)
        {
             this.signer = IssuerAndSerialNumber.getInstance(seq.getObjectAt(0));
             this.cert = Certificate.getInstance(seq.getObjectAt(1));
        }
        else
        {
             throw new IllegalArgumentException("unknown sequence in PrivateKeyStatement");
        }
    }

    public PrivateKeyPossessionStatement(IssuerAndSerialNumber signer)
    {
        this.signer = signer;
        this.cert = null;
    }

    public PrivateKeyPossessionStatement(Certificate cert)
    {
        this.signer = new IssuerAndSerialNumber(cert.getIssuer(), cert.getSerialNumber().getValue());
        this.cert = cert;
    }

    public IssuerAndSerialNumber getSigner()
    {
        return signer;
    }

    public Certificate getCert()
    {
        return cert;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(signer);

        if (cert != null)
        {
            v.add(cert);
        }

        return new DERSequence(v);
    }
}
