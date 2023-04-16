package org.bouncycastle.asn1.eac;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

public class CVCertificateRequest
    extends ASN1Object
{
    private final ASN1TaggedObject original;

    private CertificateBody certificateBody;

    private byte[] innerSignature = null;
    private byte[] outerSignature = null;

    private static final int bodyValid = 0x01;
    private static final int signValid = 0x02;

    private CVCertificateRequest(ASN1TaggedObject request)
        throws IOException
    {
        this.original = request;

        if (request.hasTag(BERTags.APPLICATION, EACTags.AUTHENTIFICATION_DATA))
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(request.getBaseUniversal(false, BERTags.SEQUENCE));

            initCertBody(ASN1TaggedObject.getInstance(seq.getObjectAt(0), BERTags.APPLICATION));

            outerSignature = ASN1OctetString.getInstance(
                ASN1TaggedObject.getInstance(seq.getObjectAt(seq.size() - 1)).getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets();
        }
        else
        {
            initCertBody(request);
        }
    }

    private void initCertBody(ASN1TaggedObject request)
        throws IOException
    {
        if (request.hasTag(BERTags.APPLICATION, EACTags.CARDHOLDER_CERTIFICATE))
        {
            int valid = 0;
            ASN1Sequence seq = ASN1Sequence.getInstance(request.getBaseUniversal(false, BERTags.SEQUENCE));
            for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
            {
                ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(en.nextElement(), BERTags.APPLICATION);
                switch (tObj.getTagNo())
                {
                case EACTags.CERTIFICATE_CONTENT_TEMPLATE:
                    certificateBody = CertificateBody.getInstance(tObj);
                    valid |= bodyValid;
                    break;
                case EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
                    innerSignature = ASN1OctetString.getInstance(
                                            tObj.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets();
                    valid |= signValid;
                    break;
                default:
                    throw new IOException("Invalid tag, not an CV Certificate Request element:" + tObj.getTagNo());
                }
            }
            if ((valid & (bodyValid | signValid)) == 0)
            {
                throw new IOException("Invalid CARDHOLDER_CERTIFICATE in request:" + request.getTagNo());
            }
        }
        else
        {
            throw new IOException("not a CARDHOLDER_CERTIFICATE in request:" + request.getTagNo());
        }
    }

    public static CVCertificateRequest getInstance(Object obj)
    {
        if (obj instanceof CVCertificateRequest)
        {
            return (CVCertificateRequest)obj;
        }
        else if (obj != null)
        {
            try
            {
                return new CVCertificateRequest(ASN1TaggedObject.getInstance(obj, BERTags.APPLICATION));
            }
            catch (IOException e)
            {
                throw new ASN1ParsingException("unable to parse data: " + e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * Returns the body of the certificate template
     *
     * @return the body.
     */
    public CertificateBody getCertificateBody()
    {
        return certificateBody;
    }

    /**
     * Return the public key data object carried in the request
     * @return  the public key
     */
    public PublicKeyDataObject getPublicKey()
    {
        return certificateBody.getPublicKey();
    }

    public byte[] getInnerSignature()
    {
        return Arrays.clone(innerSignature);
    }

    public byte[] getOuterSignature()
    {
        return Arrays.clone(outerSignature);
    }

    public boolean hasOuterSignature()
    {
        return outerSignature != null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (original != null)
        {
            return original;
        }
        else
        {
            ASN1EncodableVector v = new ASN1EncodableVector(2);

            v.add(certificateBody);
            v.add(EACTagged.create(EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, innerSignature));

            return EACTagged.create(EACTags.CARDHOLDER_CERTIFICATE, new DERSequence(v));
        }
    }
}
