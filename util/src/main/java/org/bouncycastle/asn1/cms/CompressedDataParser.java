package org.bouncycastle.asn1.cms;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Parser of <a href="https://tools.ietf.org/html/rfc3274">RFC 3274</a> {@link CompressedData} object.
 * <p>
 * <pre>
 * CompressedData ::= SEQUENCE {
 *     version CMSVersion,
 *     compressionAlgorithm CompressionAlgorithmIdentifier,
 *     encapContentInfo EncapsulatedContentInfo
 * }
 * </pre>
 */
public class CompressedDataParser
{
    private ASN1Integer _version;
    private AlgorithmIdentifier _compressionAlgorithm;
    private ContentInfoParser _encapContentInfo;

    public CompressedDataParser(
        ASN1SequenceParser seq)
        throws IOException
    {
        this._version = ASN1Integer.getInstance(seq.readObject());
        if (_version == null)
        {
            throw new IOException("CompressedData missing version");
        }

        ASN1Encodable alg = seq.readObject();
        if (alg == null)
        {
            throw new IOException("CompressedData missing compressionAlgorithm");
        }

        this._compressionAlgorithm = AlgorithmIdentifier.getInstance(alg.toASN1Primitive());

        ASN1SequenceParser encap = (ASN1SequenceParser)seq.readObject();
        if (encap == null)
        {
            throw new IOException("CompressedData missing encapContentInfo");
        }

        this._encapContentInfo = new ContentInfoParser(encap);
    }

    public ASN1Integer getVersion()
    {
        return _version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier()
    {
        return _compressionAlgorithm;
    }

    public ContentInfoParser getEncapContentInfo()
    {
        return _encapContentInfo;
    }
}
