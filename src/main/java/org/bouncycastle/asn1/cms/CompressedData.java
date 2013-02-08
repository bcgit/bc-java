package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/** 
 * RFC 3274 - CMS Compressed Data.
 * <pre>
 * CompressedData ::= SEQUENCE {
 *  version CMSVersion,
 *  compressionAlgorithm CompressionAlgorithmIdentifier,
 *  encapContentInfo EncapsulatedContentInfo
 * }
 * </pre>
 */
public class CompressedData
    extends ASN1Object
{
    private ASN1Integer           version;
    private AlgorithmIdentifier  compressionAlgorithm;
    private ContentInfo          encapContentInfo;

    public CompressedData(
        AlgorithmIdentifier compressionAlgorithm,
        ContentInfo         encapContentInfo)
    {
        this.version = new ASN1Integer(0);
        this.compressionAlgorithm = compressionAlgorithm;
        this.encapContentInfo = encapContentInfo;
    }
    
    private CompressedData(
        ASN1Sequence seq)
    {
        this.version = (ASN1Integer)seq.getObjectAt(0);
        this.compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.encapContentInfo = ContentInfo.getInstance(seq.getObjectAt(2));

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
    public static CompressedData getInstance(
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
    public static CompressedData getInstance(
        Object obj)
    {
        if (obj instanceof CompressedData)
        {
            return (CompressedData)obj;
        }

        if (obj != null)
        {
            return new CompressedData(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier()
    {
        return compressionAlgorithm;
    }

    public ContentInfo getEncapContentInfo()
    {
        return encapContentInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(compressionAlgorithm);
        v.add(encapContentInfo);

        return new BERSequence(v);
    }
}
