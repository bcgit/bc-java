package org.bouncycastle.cmc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CMCStatusInfoV2;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cmc.TaggedContentInfo;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Store;

/**
 * Carrier for a Simple PKI Response.
 * <p>
 * A Simple PKI Response is defined in RFC 5272 as a CMS SignedData object with no EncapsulatedContentInfo
 * and no SignerInfos attached. As a convenience this class also recognises the unsigned Full PKI Response
 * variant used for EST server-generated errors (RFC 7030 4.2.3 / 4.4.2): a CMS SignedData with no
 * SignerInfos whose encapsulated content is an id-cct-PKIResponse PKIResponse SEQUENCE. The structured
 * accessors {@link #getPKIResponse()}, {@link #getControlAttributes()}, {@link #getCmsContents()} and
 * {@link #getStatusInfoV2()} return the embedded PKIResponse content when present.
 * </p>
 */
public class SimplePKIResponse
    implements Encodable
{
    private final CMSSignedData certificateResponse;
    private final PKIResponse pkiResponse;

    private static ContentInfo parseBytes(byte[] responseEncoding)
        throws CMCException
    {
        try
        {
            return ContentInfo.getInstance(ASN1Primitive.fromByteArray(responseEncoding));
        }
        catch (Exception e)
        {
            throw new CMCException("malformed data: " + e.getMessage(), e);
        }
    }

    /**
     * Create a SimplePKIResponse from the passed in bytes.
     *
     * @param responseEncoding BER/DER encoding of the certificate.
     * @throws CMCException in the event of corrupted data, or an incorrect structure.
     */
    public SimplePKIResponse(byte[] responseEncoding)
        throws CMCException
    {
        this(parseBytes(responseEncoding));
    }

    /**
     * Create a SimplePKIResponse from the passed in ASN.1 structure.
     *
     * @param signedData a ContentInfo containing a SignedData.
     */
    public SimplePKIResponse(ContentInfo signedData)
        throws CMCException
    {
        try
        {
            this.certificateResponse = new CMSSignedData(signedData);
        }
        catch (CMSException e)
        {
            throw new CMCException("malformed response: " + e.getMessage(), e);
        }

        if (certificateResponse.getSignerInfos().size() != 0)
        {
            throw new CMCException("malformed response: SignerInfo structures found");
        }

        if (certificateResponse.getSignedContent() == null)
        {
            this.pkiResponse = null;
        }
        else if (CMCObjectIdentifiers.id_cct_PKIResponse.equals(certificateResponse.getSignedContentType()))
        {
            try
            {
                this.pkiResponse = PKIResponse.getInstance(
                    ASN1Primitive.fromByteArray((byte[])certificateResponse.getSignedContent().getContent()));
            }
            catch (Exception e)
            {
                throw new CMCException("malformed response: " + e.getMessage(), e);
            }
        }
        else
        {
            throw new CMCException("malformed response: Signed Content found");
        }
    }

    /**
     * Return any X.509 certificate objects in this SimplePKIResponse structure as a Store of X509CertificateHolder objects.
     *
     * @return a Store of X509CertificateHolder objects.
     */
    public Store<X509CertificateHolder> getCertificates()
    {
        return certificateResponse.getCertificates();
    }

    /**
     * Return any X.509 CRL objects in this SimplePKIResponse structure as a Store of X509CRLHolder objects.
     *
     * @return a Store of X509CRLHolder objects.
     */
    public Store<X509CRLHolder> getCRLs()
    {
        return certificateResponse.getCRLs();
    }

    /**
     * Return the embedded PKIResponse content, if present.
     *
     * @return the parsed PKIResponse, or null if the SignedData has no encapsulated PKIResponse.
     */
    public PKIResponse getPKIResponse()
    {
        return pkiResponse;
    }

    /**
     * Return the controlSequence of the embedded PKIResponse as an array of TaggedAttribute, or
     * an empty array if no PKIResponse is present.
     */
    public TaggedAttribute[] getControlAttributes()
    {
        if (pkiResponse == null)
        {
            return new TaggedAttribute[0];
        }

        int size = pkiResponse.getControlSequence().size();
        TaggedAttribute[] attrs = new TaggedAttribute[size];
        for (int i = 0; i != size; i++)
        {
            attrs[i] = TaggedAttribute.getInstance(pkiResponse.getControlSequence().getObjectAt(i));
        }
        return attrs;
    }

    /**
     * Return the cmsSequence of the embedded PKIResponse as an array of TaggedContentInfo, or
     * an empty array if no PKIResponse is present.
     */
    public TaggedContentInfo[] getCmsContents()
    {
        if (pkiResponse == null)
        {
            return new TaggedContentInfo[0];
        }

        int size = pkiResponse.getCmsSequence().size();
        TaggedContentInfo[] arr = new TaggedContentInfo[size];
        for (int i = 0; i != size; i++)
        {
            arr[i] = TaggedContentInfo.getInstance(pkiResponse.getCmsSequence().getObjectAt(i));
        }
        return arr;
    }

    /**
     * Convenience accessor for the first id-cmc-statusInfoV2 attribute in the PKIResponse
     * controlSequence (typical of an EST server-generated error response).
     *
     * @return the CMCStatusInfoV2 if present, otherwise null.
     */
    public CMCStatusInfoV2 getStatusInfoV2()
    {
        TaggedAttribute[] attrs = getControlAttributes();
        for (int i = 0; i != attrs.length; i++)
        {
            if (CMCObjectIdentifiers.id_cmc_statusInfoV2.equals(attrs[i].getAttrType())
                && attrs[i].getAttrValues().size() != 0)
            {
                return CMCStatusInfoV2.getInstance(attrs[i].getAttrValues().getObjectAt(0));
            }
        }
        return null;
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return certificateResponse.getEncoded();
    }
}
