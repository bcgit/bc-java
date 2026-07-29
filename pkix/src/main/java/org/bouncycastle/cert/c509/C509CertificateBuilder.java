package org.bouncycastle.cert.c509;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cbor.c509.C509Certificate;
import org.bouncycastle.cbor.c509.C509ConversionOptions;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.ContentSigner;

/**
 * Builder for natively signed C509 certificates (type 2,
 * draft-ietf-cose-cbor-encoded-cert-20), mirroring the X.509 v3 certificate builder.
 * The signature is computed directly over the TBSCertificate CBOR sequence, so no
 * ASN.1 processing is needed to verify the result.
 * <p>
 * A CBOR re-encoded certificate (type 3) is not built directly - issue an X.509
 * certificate in the usual way and convert it with
 * {@link C509Certificate#fromX509Certificate(org.bouncycastle.asn1.x509.Certificate, C509ConversionOptions)}.
 */
public class C509CertificateBuilder
{
    private final X500Name issuer;
    private final BigInteger serialNumber;
    private final Date notBefore;
    private final Date notAfter;
    private final X500Name subject;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;
    private final ExtensionsGenerator extGenerator = new ExtensionsGenerator();

    private C509ConversionOptions options = C509ConversionOptions.DEFAULT;

    /**
     * Base constructor.
     *
     * @param issuer the certificate issuer.
     * @param serialNumber the certificate serial number.
     * @param notBefore the date before which the certificate is not valid.
     * @param notAfter the date after which the certificate is not valid, or null for
     *        no well-defined expiration date.
     * @param subject the certificate subject.
     * @param subjectPublicKeyInfo the info structure for the public key to be
     *        associated with this certificate.
     */
    public C509CertificateBuilder(X500Name issuer, BigInteger serialNumber, Date notBefore, Date notAfter,
        X500Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.subject = subject;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
    }

    /**
     * Set the conversion options - point compression in particular. A natively
     * signed certificate stores a compressed Weierstrass key with the SEC 1 octets
     * 0x02/0x03.
     */
    public C509CertificateBuilder setConversionOptions(C509ConversionOptions options)
    {
        this.options = options;
        return this;
    }

    /**
     * Add a given extension field for the standard extensions tag.
     */
    public C509CertificateBuilder addExtension(ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value)
        throws CertIOException
    {
        try
        {
            extGenerator.addExtension(oid, isCritical, value);
        }
        catch (IOException e)
        {
            throw new CertIOException("cannot encode extension: " + e.getMessage(), e);
        }
        return this;
    }

    /**
     * Add a given extension field for the standard extensions tag, with the value
     * already encoded.
     */
    public C509CertificateBuilder addExtension(ASN1ObjectIdentifier oid, boolean isCritical, byte[] encodedValue)
    {
        extGenerator.addExtension(oid, isCritical, encodedValue);
        return this;
    }

    /**
     * Generate the certificate, signing the TBSCertificate CBOR sequence with the
     * given signer.
     */
    public C509CertificateHolder build(ContentSigner signer)
        throws CertIOException
    {
        try
        {
            byte[] tbsCertificate = C509Certificate.createTBSCertificate(C509Certificate.TYPE_NATIVE,
                serialNumber, signer.getAlgorithmIdentifier(), issuer, notBefore, notAfter, subject,
                subjectPublicKeyInfo, extGenerator.isEmpty() ? null : extGenerator.generate(), options);

            OutputStream sOut = signer.getOutputStream();
            sOut.write(tbsCertificate);
            sOut.close();

            return new C509CertificateHolder(C509Certificate.create(tbsCertificate, signer.getSignature(), options));
        }
        catch (IOException e)
        {
            throw new CertIOException("cannot produce certificate: " + e.getMessage(), e);
        }
    }
}
