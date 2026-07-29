package org.bouncycastle.cert.c509;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cbor.c509.C509Attribute;
import org.bouncycastle.cbor.c509.C509CertificationRequest;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Encodable;

/**
 * Holding class for a C509 certification request (Section 4 of
 * draft-ietf-cose-cbor-encoded-cert-20), mirroring the PKCS#10 holding class.
 * <p>
 * For a natively signed request (type 2) the signature covers the
 * TBSCertificationRequest CBOR sequence; for a re-encoded RFC 2986 request (type 3)
 * it covers the reconstructed DER CertificationRequestInfo.
 */
public class C509CertificationRequestHolder
    implements Encodable
{
    private final C509CertificationRequest request;

    /**
     * Base constructor.
     */
    public C509CertificationRequestHolder(C509CertificationRequest request)
    {
        if (request == null)
        {
            throw new NullPointerException("'request' cannot be null");
        }
        this.request = request;
    }

    /**
     * Create a holder from the CBOR encoding of a C509 certification request.
     */
    public C509CertificationRequestHolder(byte[] encoding)
        throws IOException
    {
        this(C509CertificationRequest.getInstance(encoding));
    }

    /**
     * Return the certification request this holder wraps.
     */
    public C509CertificationRequest getC509CertificationRequest()
    {
        return request;
    }

    public int getRequestType()
    {
        return request.getRequestType();
    }

    public X500Name getSubject()
    {
        return request.getSubject();
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return request.getSubjectPublicKeyInfo();
    }

    public C509Attribute[] getAttributes()
    {
        return request.getAttributes();
    }

    /**
     * Validate the signature (the proof-of-possession) on this certification request.
     *
     * @param verifierProvider a provider of verifiers built on the request's subject
     *        public key.
     * @return true if the signature verifies, false otherwise.
     */
    public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
        throws CertException
    {
        try
        {
            ContentVerifier verifier = verifierProvider.get(
                request.getSubjectSignatureAlgorithm().toX509AlgorithmIdentifier());

            OutputStream sOut = verifier.getOutputStream();
            sOut.write(getSignedBytes());
            sOut.close();

            return verifier.verify(request.getSignature());
        }
        catch (Exception e)
        {
            throw new CertException("unable to process signature: " + e.getMessage(), e);
        }
    }

    /**
     * Return the bytes the request signature is computed over: the
     * TBSCertificationRequest CBOR sequence for a natively signed request, the
     * reconstructed DER CertificationRequestInfo for a re-encoded one.
     */
    public byte[] getSignedBytes()
        throws IOException
    {
        if (request.getRequestType() == C509CertificationRequest.TYPE_NATIVE)
        {
            return request.getTBSCertificationRequestEncoded();
        }
        return request.toCertificationRequest().getCertificationRequestInfo().getEncoded(ASN1Encoding.DER);
    }

    /**
     * Return the CBOR encoding of the certification request.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return request.getEncoded();
    }
}
