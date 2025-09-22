package org.bouncycastle.asn1.pkcs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;

public class RSAESOAEPparams
    extends ASN1Object
{
    private AlgorithmIdentifier hashAlgorithm;
    private AlgorithmIdentifier maskGenAlgorithm;
    private AlgorithmIdentifier pSourceAlgorithm;
    
    public final static AlgorithmIdentifier DEFAULT_HASH_ALGORITHM = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
    public final static AlgorithmIdentifier DEFAULT_MASK_GEN_FUNCTION = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, DEFAULT_HASH_ALGORITHM);
    public final static AlgorithmIdentifier DEFAULT_P_SOURCE_ALGORITHM = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]));
    
    public static RSAESOAEPparams getInstance(
        Object  obj)
    {
        if (obj instanceof RSAESOAEPparams)
        {
            return (RSAESOAEPparams)obj;
        }
        else if (obj != null)
        {
            return new RSAESOAEPparams(ASN1Sequence.getInstance(obj));
        }

        return null;
    }
    
    /**
     * The default version
     */
    public RSAESOAEPparams()
    {
        hashAlgorithm = DEFAULT_HASH_ALGORITHM;
        maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
        pSourceAlgorithm = DEFAULT_P_SOURCE_ALGORITHM;
    }
    
    public RSAESOAEPparams(
        AlgorithmIdentifier hashAlgorithm,
        AlgorithmIdentifier maskGenAlgorithm,
        AlgorithmIdentifier pSourceAlgorithm)
    {
        this.hashAlgorithm = hashAlgorithm;
        this.maskGenAlgorithm = maskGenAlgorithm;
        this.pSourceAlgorithm = pSourceAlgorithm;
    }

    private RSAESOAEPparams(
        ASN1Sequence seq)
    {
        hashAlgorithm = DEFAULT_HASH_ALGORITHM;
        maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
        pSourceAlgorithm = DEFAULT_P_SOURCE_ALGORITHM;
        
        for (int i = 0; i != seq.size(); i++)
        {
            ASN1TaggedObject    o = (ASN1TaggedObject)seq.getObjectAt(i);
            
            switch (o.getTagNo())
            {
            case 0:
                hashAlgorithm = AlgorithmIdentifier.getInstance(o, true);
                break;
            case 1:
                maskGenAlgorithm = AlgorithmIdentifier.getInstance(o, true);
                break;
            case 2:
                pSourceAlgorithm = AlgorithmIdentifier.getInstance(o, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag");
            }
        }
    }
    
    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }
    
    public AlgorithmIdentifier getMaskGenAlgorithm()
    {
        return maskGenAlgorithm;
    }
    
    public AlgorithmIdentifier getPSourceAlgorithm()
    {
        return pSourceAlgorithm;
    }

    public RSAESOAEPparams withDefaultPSource()
    {
        if (DEFAULT_P_SOURCE_ALGORITHM == pSourceAlgorithm)
        {
            return this;
        }

        return new RSAESOAEPparams(hashAlgorithm, maskGenAlgorithm, DEFAULT_P_SOURCE_ALGORITHM);
    }

    /**
     * <pre>
     *  RSAES-OAEP-params ::= SEQUENCE {
     *     hashAlgorithm      [0] OAEP-PSSDigestAlgorithms     DEFAULT sha1,
     *     maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
     *     pSourceAlgorithm   [2] PKCS1PSourceAlgorithms  DEFAULT pSpecifiedEmpty
     *   }
     *  
     *   OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
     *     { OID id-sha1 PARAMETERS NULL   }|
     *     { OID id-sha256 PARAMETERS NULL }|
     *     { OID id-sha384 PARAMETERS NULL }|
     *     { OID id-sha512 PARAMETERS NULL },
     *     ...  -- Allows for future expansion --
     *   }
     *   PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
     *     { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
     *    ...  -- Allows for future expansion --
     *   }
     *   PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
     *     { OID id-pSpecified PARAMETERS OCTET STRING },
     *     ...  -- Allows for future expansion --
     *  }
     * </pre>
     * @return the asn1 primitive representing the parameters.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        
        if (!hashAlgorithm.equals(DEFAULT_HASH_ALGORITHM))
        {
            v.add(new DERTaggedObject(true, 0, hashAlgorithm));
        }
        
        if (!maskGenAlgorithm.equals(DEFAULT_MASK_GEN_FUNCTION))
        {
            v.add(new DERTaggedObject(true, 1, maskGenAlgorithm));
        }
        
        if (!pSourceAlgorithm.equals(DEFAULT_P_SOURCE_ALGORITHM))
        {
            v.add(new DERTaggedObject(true, 2, pSourceAlgorithm));
        }

        return new DERSequence(v);
    }
}
