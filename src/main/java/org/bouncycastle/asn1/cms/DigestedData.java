package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/** 
 * RFC 3274 - CMS Digest Data.
 * <pre>
 * DigestedData ::= SEQUENCE {
 *               version CMSVersion,
 *               digestAlgorithm DigestAlgorithmIdentifier,
 *               encapContentInfo EncapsulatedContentInfo,
 *               digest Digest }
 * </pre>
 */
public class DigestedData
    extends ASN1Object
{
    private ASN1Integer           version;
    private AlgorithmIdentifier  digestAlgorithm;
    private ContentInfo          encapContentInfo;
    private ASN1OctetString      digest;

    public DigestedData(
        AlgorithmIdentifier digestAlgorithm,
        ContentInfo encapContentInfo,
        byte[]      digest)
    {
        this.version = new ASN1Integer(0);
        this.digestAlgorithm = digestAlgorithm;
        this.encapContentInfo = encapContentInfo;
        this.digest = new DEROctetString(digest);
    }

    private DigestedData(
        ASN1Sequence seq)
    {
        this.version = (ASN1Integer)seq.getObjectAt(0);
        this.digestAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.encapContentInfo = ContentInfo.getInstance(seq.getObjectAt(2));
        this.digest = ASN1OctetString.getInstance(seq.getObjectAt(3));
    }

    /**
     * return a CompressedData object from a tagged object.
     *
     * @param _ato the tagged object holding the object we want.
     * @param _explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static DigestedData getInstance(
        ASN1TaggedObject _ato,
        boolean _explicit)
    {
        return getInstance(ASN1Sequence.getInstance(_ato, _explicit));
    }
    
    /**
     * return a CompressedData object from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DigestedData getInstance(
        Object obj)
    {
        if (obj instanceof DigestedData)
        {
            return (DigestedData)obj;
        }
        
        if (obj != null)
        {
            return new DigestedData(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgorithm;
    }

    public ContentInfo getEncapContentInfo()
    {
        return encapContentInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(digestAlgorithm);
        v.add(encapContentInfo);
        v.add(digest);

        return new BERSequence(v);
    }

    public byte[] getDigest()
    {
        return digest.getOctets();
    }
}
