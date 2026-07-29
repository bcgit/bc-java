package org.bouncycastle.cert.c509;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cbor.c509.C509CertificationRequest;
import org.bouncycastle.cbor.c509.C509ConversionOptions;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.ContentSigner;

/**
 * Builder for natively signed C509 certification requests (type 2, Section 4 of
 * draft-ietf-cose-cbor-encoded-cert-20). The proof-of-possession signature is
 * computed directly over the TBSCertificationRequest CBOR sequence.
 */
public class C509CertificationRequestBuilder
{
    private final X500Name subject;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;

    private Extensions extensionRequest;
    private String challengePassword;
    private C509ConversionOptions options = C509ConversionOptions.DEFAULT;

    /**
     * Base constructor.
     *
     * @param subject the X.500 name defining the certificate subject.
     * @param subjectPublicKeyInfo the info structure for the public key to be
     *        associated with the request.
     */
    public C509CertificationRequestBuilder(X500Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        this.subject = subject;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
    }

    /**
     * Set the extensions requested of the CA (the RFC 2985 extensionRequest
     * attribute).
     */
    public C509CertificationRequestBuilder setExtensionRequest(Extensions extensionRequest)
    {
        this.extensionRequest = extensionRequest;
        return this;
    }

    /**
     * Set a challenge password (the RFC 2985 challengePassword attribute). In a
     * natively signed request the password is always carried as a UTF-8 text string.
     */
    public C509CertificationRequestBuilder setChallengePassword(String challengePassword)
    {
        this.challengePassword = challengePassword;
        return this;
    }

    /**
     * Set the conversion options - point compression in particular.
     */
    public C509CertificationRequestBuilder setConversionOptions(C509ConversionOptions options)
    {
        this.options = options;
        return this;
    }

    /**
     * Generate the certification request, signing the TBSCertificationRequest CBOR
     * sequence with the given signer.
     */
    public C509CertificationRequestHolder build(ContentSigner signer)
        throws CertIOException
    {
        try
        {
            byte[] tbsRequest = C509CertificationRequest.createTBSCertificationRequest(
                C509CertificationRequest.TYPE_NATIVE, signer.getAlgorithmIdentifier(), subject,
                subjectPublicKeyInfo, extensionRequest, challengePassword, options);

            OutputStream sOut = signer.getOutputStream();
            sOut.write(tbsRequest);
            sOut.close();

            return new C509CertificationRequestHolder(
                C509CertificationRequest.create(tbsRequest, signer.getSignature(), options));
        }
        catch (IOException e)
        {
            throw new CertIOException("cannot produce certification request: " + e.getMessage(), e);
        }
    }
}
