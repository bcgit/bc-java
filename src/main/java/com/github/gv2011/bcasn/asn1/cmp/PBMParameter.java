package com.github.gv2011.bcasn.asn1.cmp;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1OctetString;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DEROctetString;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.x509.AlgorithmIdentifier;

public class PBMParameter
    extends ASN1Object
{
    private ASN1OctetString salt;
    private AlgorithmIdentifier owf;
    private ASN1Integer iterationCount;
    private AlgorithmIdentifier mac;

    private PBMParameter(ASN1Sequence seq)
    {
        salt = ASN1OctetString.getInstance(seq.getObjectAt(0));
        owf = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        iterationCount = ASN1Integer.getInstance(seq.getObjectAt(2));
        mac = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
    }

    public static PBMParameter getInstance(Object o)
    {
        if (o instanceof PBMParameter)
        {
            return (PBMParameter)o;
        }

        if (o != null)
        {
            return new PBMParameter(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PBMParameter(
        byte[] salt,
        AlgorithmIdentifier owf,
        int iterationCount,
        AlgorithmIdentifier mac)
    {
        this(new DEROctetString(salt), owf,
             new ASN1Integer(iterationCount), mac);
    }

    public PBMParameter(
        ASN1OctetString salt,
        AlgorithmIdentifier owf,
        ASN1Integer iterationCount,
        AlgorithmIdentifier mac)
    {
        this.salt = salt;
        this.owf = owf;
        this.iterationCount = iterationCount;
        this.mac = mac;
    }

    public ASN1OctetString getSalt()
    {
        return salt;
    }

    public AlgorithmIdentifier getOwf()
    {
        return owf;
    }

    public ASN1Integer getIterationCount()
    {
        return iterationCount;
    }

    public AlgorithmIdentifier getMac()
    {
        return mac;
    }

    /**
     * <pre>
     *  PBMParameter ::= SEQUENCE {
     *                        salt                OCTET STRING,
     *                        -- note:  implementations MAY wish to limit acceptable sizes
     *                        -- of this string to values appropriate for their environment
     *                        -- in order to reduce the risk of denial-of-service attacks
     *                        owf                 AlgorithmIdentifier,
     *                        -- AlgId for a One-Way Function (SHA-1 recommended)
     *                        iterationCount      INTEGER,
     *                        -- number of times the OWF is applied
     *                        -- note:  implementations MAY wish to limit acceptable sizes
     *                        -- of this integer to values appropriate for their environment
     *                        -- in order to reduce the risk of denial-of-service attacks
     *                        mac                 AlgorithmIdentifier
     *                        -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
     *    }   -- or HMAC [RFC2104, RFC2202])
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(salt);
        v.add(owf);
        v.add(iterationCount);
        v.add(mac);
        
        return new DERSequence(v);
    }
}
