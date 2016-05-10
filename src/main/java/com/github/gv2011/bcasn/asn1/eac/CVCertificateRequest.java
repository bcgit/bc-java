package com.github.gv2011.bcasn.asn1.eac;

import java.io.IOException;
import java.util.Enumeration;

import com.github.gv2011.bcasn.asn1.ASN1ApplicationSpecific;
import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1ParsingException;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.BERTags;
import com.github.gv2011.bcasn.asn1.DERApplicationSpecific;
import com.github.gv2011.bcasn.asn1.DEROctetString;

//import java.math.BigInteger;


public class CVCertificateRequest
    extends ASN1Object
{
    private CertificateBody certificateBody;

    private byte[] innerSignature = null;
    private byte[] outerSignature = null;

    private int valid;

    private static int bodyValid = 0x01;
    private static int signValid = 0x02;

    private CVCertificateRequest(ASN1ApplicationSpecific request)
        throws IOException
    {
        if (request.getApplicationTag() == EACTags.AUTHENTIFICATION_DATA)
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

    ASN1ObjectIdentifier signOid = null;
    ASN1ObjectIdentifier keyOid = null;

    public static byte[] ZeroArray = new byte[]{0};


    String strCertificateHolderReference;

    byte[] encodedAuthorityReference;

    int ProfileId;

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
        return innerSignature;
    }

    public byte[] getOuterSignature()
    {
        return outerSignature;
    }

    byte[] certificate = null;
    protected String overSignerReference = null;

    public boolean hasOuterSignature()
    {
        return outerSignature != null;
    }

    byte[] encoded;

    PublicKeyDataObject iso7816PubKey = null;

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

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
