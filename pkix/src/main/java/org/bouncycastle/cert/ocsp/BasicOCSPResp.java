package org.bouncycastle.cert.ocsp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Encodable;

/**
 * OCSP RFC 2560, RFC 6960
 * <pre>
 * BasicOCSPResponse       ::= SEQUENCE {
 *    tbsResponseData      ResponseData,
 *    signatureAlgorithm   AlgorithmIdentifier,
 *    signature            BIT STRING,
 *    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 * </pre>
 */
public class BasicOCSPResp
    implements Encodable
{
    private BasicOCSPResponse   resp;
    private ResponseData        data;
    private Extensions extensions;

    public BasicOCSPResp(
        BasicOCSPResponse   resp)
    {
        this.resp = resp;
        this.data = resp.getTbsResponseData();
        this.extensions = Extensions.getInstance(resp.getTbsResponseData().getResponseExtensions());
    }

    /**
     * Return the DER encoding of the tbsResponseData field.
     * @return DER encoding of tbsResponseData
     */
    public byte[] getTBSResponseData()
    {
        try
        {
            return resp.getTbsResponseData().getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    /**
     * Return the algorithm identifier describing the signature used in the response.
     *
     * @return an AlgorithmIdentifier
     */
    public AlgorithmIdentifier getSignatureAlgorithmID()
    {
        return resp.getSignatureAlgorithm();
    }

    public int getVersion()
    {
        return data.getVersion().intValueExact() + 1;
    }

    public RespID getResponderId()
    {
        return new RespID(data.getResponderID());
    }

    public Date getProducedAt()
    {
        return OCSPUtils.extractDate(data.getProducedAt());
    }

    public SingleResp[] getResponses()
    {
        ASN1Sequence    s = data.getResponses();
        SingleResp[]    rs = new SingleResp[s.size()];

        for (int i = 0; i != rs.length; i++)
        {
            rs[i] = new SingleResp(SingleResponse.getInstance(s.getObjectAt(i)));
        }

        return rs;
    }

    public boolean hasExtensions()
   {
       return extensions != null;
   }

   public Extension getExtension(ASN1ObjectIdentifier oid)
   {
       if (extensions != null)
       {
           return extensions.getExtension(oid);
       }

       return null;
   }

   public List getExtensionOIDs()
   {
       return OCSPUtils.getExtensionOIDs(extensions);
   }

   public Set getCriticalExtensionOIDs()
   {
       return OCSPUtils.getCriticalExtensionOIDs(extensions);
   }

   public Set getNonCriticalExtensionOIDs()
   {
       return OCSPUtils.getNonCriticalExtensionOIDs(extensions);
   }


    public ASN1ObjectIdentifier getSignatureAlgOID()
    {
        return resp.getSignatureAlgorithm().getAlgorithm();
    }

    public byte[] getSignature()
    {
        return resp.getSignature().getOctets();
    }

    public X509CertificateHolder[] getCerts()
    {
        //
        // load the certificates if we have any
        //
        if (resp.getCerts() != null)
        {
            ASN1Sequence s = resp.getCerts();

            if (s != null)
            {
                X509CertificateHolder[] certs = new X509CertificateHolder[s.size()];

                for (int i = 0; i != certs.length; i++)
                {
                    certs[i] = new X509CertificateHolder(Certificate.getInstance(s.getObjectAt(i)));
                }

                return certs;
            }

            return OCSPUtils.EMPTY_CERTS;
        }
        else
        {
            return OCSPUtils.EMPTY_CERTS;
        }
    }

    /**
     * verify the signature against the tbsResponseData object we contain.
     */
    public boolean isSignatureValid(
        ContentVerifierProvider verifierProvider)
        throws OCSPException
    {
        try
        {
            ContentVerifier verifier = verifierProvider.get(resp.getSignatureAlgorithm());
            OutputStream vOut = verifier.getOutputStream();

            vOut.write(resp.getTbsResponseData().getEncoded(ASN1Encoding.DER));
            vOut.close();

            return verifier.verify(this.getSignature());
        }
        catch (Exception e)
        {
            throw new OCSPException("exception processing sig: " + e, e);
        }
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return resp.getEncoded();
    }
    
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        
        if (!(o instanceof BasicOCSPResp))
        {
            return false;
        }
        
        BasicOCSPResp r = (BasicOCSPResp)o;
        
        return resp.equals(r.resp);
    }
    
    public int hashCode()
    {
        return resp.hashCode();
    }
}
