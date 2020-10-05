package org.bouncycastle.asn1.eac;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;

public class CVCertificateRequest
    extends ASN1Object
{
    private final ASN1ApplicationSpecific original;

    private CertificateBody certificateBody;

    private byte[] innerSignature = null;
    private byte[] outerSignature = null;

    private static final int bodyValid = 0x01;
    private static final int signValid = 0x02;

    private CVCertificateRequest(ASN1ApplicationSpecific request)
        throws IOException
    {
        this.original = request;

        if (request.isConstructed() && request.getApplicationTag() == EACTags.AUTHENTIFICATION_DATA)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(request.getObject(BERTags.SEQUENCE));

            initCertBody(ASN1ApplicationSpecific.getInstance(seq.getObjectAt(0)));

            outerSignature = ASN1ApplicationSpecific.getInstance(seq.getObjectAt(seq.size() - 1)).getContents();
        }
        else
        {
            initCertBody(request);
        }
    }

    private void initCertBody(ASN1ApplicationSpecific request)
        throws IOException
    {
        if (request.getApplicationTag() == EACTags.CARDHOLDER_CERTIFICATE)
        {
            int valid = 0;
            ASN1Sequence seq = ASN1Sequence.getInstance(request.getObject(BERTags.SEQUENCE));
            for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
            {
                ASN1ApplicationSpecific obj = ASN1ApplicationSpecific.getInstance(en.nextElement());
                switch (obj.getApplicationTag())
                {
                case EACTags.CERTIFICATE_CONTENT_TEMPLATE:
                    certificateBody = CertificateBody.getInstance(obj);
                    valid |= bodyValid;
                    break;
                case EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
                    innerSignature = obj.getContents();
                    valid |= signValid;
                    break;
                default:
                    throw new IOException("Invalid tag, not an CV Certificate Request element:" + obj.getApplicationTag());
                }
            }
            if ((valid & (bodyValid | signValid)) == 0)
            {
                throw new IOException("Invalid CARDHOLDER_CERTIFICATE in request:" + request.getApplicationTag());
            }
        }
        else
        {
            throw new IOException("not a CARDHOLDER_CERTIFICATE in request:" + request.getApplicationTag());
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
                return new CVCertificateRequest(ASN1ApplicationSpecific.getInstance(obj));
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

            try
            {
                v.add(new DERApplicationSpecific(false, EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, new DEROctetString(innerSignature)));
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to convert signature!");
            }

            return new DERApplicationSpecific(EACTags.CARDHOLDER_CERTIFICATE, v);
        }
    }
}
