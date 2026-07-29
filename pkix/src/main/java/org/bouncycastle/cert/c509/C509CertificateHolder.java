package org.bouncycastle.cert.c509;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cbor.c509.C509AlgorithmIdentifier;
import org.bouncycastle.cbor.c509.C509Certificate;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Encodable;

/**
 * Holding class for a C509 certificate (draft-ietf-cose-cbor-encoded-cert-20),
 * mirroring {@link X509CertificateHolder}.
 * <p>
 * For a natively signed certificate (type 2) the signature covers the
 * TBSCertificate CBOR sequence and {@link #isSignatureValid} checks it directly over
 * those bytes. For a CBOR re-encoded X.509 certificate (type 3) the signature covers
 * the reconstructed DER TBSCertificate, and the holder can also be turned back into
 * an {@link X509CertificateHolder} with {@link #toX509CertificateHolder()}.
 */
public class C509CertificateHolder
    implements Encodable
{
    private final C509Certificate certificate;

    /**
     * Base constructor.
     *
     * @param certificate the certificate this holder wraps.
     */
    public C509CertificateHolder(C509Certificate certificate)
    {
        if (certificate == null)
        {
            throw new NullPointerException("'certificate' cannot be null");
        }
        this.certificate = certificate;
    }

    /**
     * Create a holder from the CBOR encoding of a C509 certificate.
     */
    public C509CertificateHolder(byte[] encoding)
        throws IOException
    {
        this(C509Certificate.getInstance(encoding));
    }

    /**
     * Return the certificate this holder wraps.
     */
    public C509Certificate getC509Certificate()
    {
        return certificate;
    }

    /**
     * Return the certificate type ({@link C509Certificate#TYPE_NATIVE} or
     * {@link C509Certificate#TYPE_REENCODED_X509}).
     */
    public int getCertificateType()
    {
        return certificate.getCertificateType();
    }

    public BigInteger getSerialNumber()
    {
        return certificate.getSerialNumber();
    }

    public X500Name getIssuer()
    {
        return certificate.getIssuer();
    }

    public X500Name getSubject()
    {
        return certificate.getSubject();
    }

    public Date getNotBefore()
    {
        return new Date(certificate.getNotBefore() * 1000);
    }

    /**
     * Return the end of the validity period. A certificate with no well-defined
     * expiration date (99991231235959Z) returns the corresponding date.
     */
    public Date getNotAfter()
    {
        return new Date(certificate.getNotAfter() * 1000);
    }

    /**
     * Return whether or not the certificate is valid on the date given.
     */
    public boolean isValidOn(Date date)
    {
        if (date == null)
        {
            throw new NullPointerException("'date' cannot be null");
        }
        long seconds = date.getTime() / 1000;
        return seconds >= certificate.getNotBefore() && seconds <= certificate.getNotAfter();
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return certificate.getSubjectPublicKeyInfo();
    }

    public C509AlgorithmIdentifier getSignatureAlgorithm()
    {
        return certificate.getIssuerSignatureAlgorithm();
    }

    /**
     * Return the X.509 view of the extensions, or null if there are none.
     */
    public Extensions getExtensions()
    {
        return certificate.getExtensions().toX509Extensions();
    }

    /**
     * Validate the signature on this certificate.
     *
     * @param verifierProvider a provider of verifiers built on the issuer's public
     *        key.
     * @return true if the signature verifies, false otherwise.
     */
    public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
        throws CertException
    {
        try
        {
            ContentVerifier verifier = verifierProvider.get(
                certificate.getIssuerSignatureAlgorithm().toX509AlgorithmIdentifier());

            OutputStream sOut = verifier.getOutputStream();
            sOut.write(getSignedBytes());
            sOut.close();

            return verifier.verify(certificate.getSignature());
        }
        catch (Exception e)
        {
            throw new CertException("unable to process signature: " + e.getMessage(), e);
        }
    }

    /**
     * Return the bytes the certificate signature is computed over: the TBSCertificate
     * CBOR sequence for a natively signed certificate, the reconstructed DER
     * TBSCertificate for a re-encoded one.
     */
    public byte[] getSignedBytes()
        throws IOException
    {
        if (certificate.getCertificateType() == C509Certificate.TYPE_NATIVE)
        {
            return certificate.getTBSCertificateEncoded();
        }
        return certificate.toX509Certificate().getTBSCertificate().getEncoded(ASN1Encoding.DER);
    }

    /**
     * Return the X.509 holder for a CBOR re-encoded (type 3) certificate.
     *
     * @throws IllegalStateException if this is a natively signed certificate.
     */
    public X509CertificateHolder toX509CertificateHolder()
        throws IOException
    {
        try
        {
            return new X509CertificateHolder(certificate.toX509Certificate().getEncoded(ASN1Encoding.DER));
        }
        catch (RuntimeException e)
        {
            throw new CertIOException("unable to reconstruct X.509 certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Return the CBOR encoding of the certificate.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return certificate.getEncoded();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof C509CertificateHolder))
        {
            return false;
        }
        return certificate.equals(((C509CertificateHolder)o).certificate);
    }

    public int hashCode()
    {
        return certificate.hashCode();
    }
}
