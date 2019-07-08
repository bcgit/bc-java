package org.bouncycastle.pqc.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

/**
 * Return the keyData to encode in the PrivateKeyInfo structure.
 * <p>
 * The ASN.1 definition of the key structure is
 * </p>
 * <pre>
 *   McElieceCCA2PrivateKey ::= SEQUENCE {
 *     m             INTEGER                  -- extension degree of the field
 *     k             INTEGER                  -- dimension of the code
 *     field         OCTET STRING             -- field polynomial
 *     goppaPoly     OCTET STRING             -- irreducible Goppa polynomial
 *     p             OCTET STRING             -- permutation vector
 *     digest        AlgorithmIdentifier      -- algorithm identifier for CCA2 digest
 *   }
 * </pre>
 */
public class McElieceCCA2PrivateKey
    extends ASN1Object
{
    private int n;
    private int k;
    private byte[] encField;
    private byte[] encGp;
    private byte[] encP;
    private AlgorithmIdentifier digest;


    public McElieceCCA2PrivateKey(int n, int k, GF2mField field, PolynomialGF2mSmallM goppaPoly, Permutation p, AlgorithmIdentifier digest)
    {
        this.n = n;
        this.k = k;
        this.encField = field.getEncoded();
        this.encGp = goppaPoly.getEncoded();
        this.encP = p.getEncoded();
        this.digest = digest;
    }

    private McElieceCCA2PrivateKey(ASN1Sequence seq)
    {
        n = ((ASN1Integer)seq.getObjectAt(0)).intValueExact();

        k = ((ASN1Integer)seq.getObjectAt(1)).intValueExact();

        encField = ((ASN1OctetString)seq.getObjectAt(2)).getOctets();

        encGp = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();

        encP = ((ASN1OctetString)seq.getObjectAt(4)).getOctets();

        digest = AlgorithmIdentifier.getInstance(seq.getObjectAt(5));
    }

    public int getN()
    {
        return n;
    }

    public int getK()
    {
        return k;
    }

    public GF2mField getField()
    {
        return new GF2mField(encField);
    }

    public PolynomialGF2mSmallM getGoppaPoly()
    {
        return new PolynomialGF2mSmallM(this.getField(), encGp);
    }

    public Permutation getP()
    {
        return new Permutation(encP);
    }

    public AlgorithmIdentifier getDigest()
    {
        return digest;
    }

    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector v = new ASN1EncodableVector();

        // encode <n>
        v.add(new ASN1Integer(n));

        // encode <k>
        v.add(new ASN1Integer(k));

        // encode <field>
        v.add(new DEROctetString(encField));

        // encode <gp>
        v.add(new DEROctetString(encGp));

        // encode <p>
        v.add(new DEROctetString(encP));

        v.add(digest);

        return new DERSequence(v);
    }

    public static McElieceCCA2PrivateKey getInstance(Object o)
    {
        if (o instanceof McElieceCCA2PrivateKey)
        {
            return (McElieceCCA2PrivateKey)o;
        }
        else if (o != null)
        {
            return new McElieceCCA2PrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
