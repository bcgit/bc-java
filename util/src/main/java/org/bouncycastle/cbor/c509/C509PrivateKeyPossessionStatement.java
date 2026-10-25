package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.PrivateKeyPossessionStatement;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.util.Exceptions;

/**
 * The C509 form of the RFC 9883 privateKeyPossessionStatement certification request
 * attribute (Section 4.3.3 of draft-ietf-cose-cbor-encoded-cert-21):
 * <pre>
 * PrivateKeyPossessionStatement = [
 *   issuer: Name,
 *   certificateSerialNumber: CertificateSerialNumber,
 *   cert: C509CertData / null,
 * ]
 * </pre>
 * The issuer and serial number name the signature certificate whose holder vouches
 * for possession of the key-establishment private key; the certificate itself may be
 * carried alongside, as a C509 certificate of either type. In a CBOR re-encoded
 * (type 3) request the certificate must itself be a re-encoded (type 3) C509
 * certificate, or the RFC 2986 request cannot be reconstructed.
 */
public class C509PrivateKeyPossessionStatement
{
    private final X500Name issuer;
    private final BigInteger serialNumber;
    private final C509Certificate certificate;

    /**
     * A statement naming the signature certificate without carrying it.
     */
    public C509PrivateKeyPossessionStatement(X500Name issuer, BigInteger serialNumber)
    {
        this(issuer, serialNumber, null);
    }

    /**
     * A statement carrying the signature certificate, named by its own issuer and
     * serial number.
     */
    public C509PrivateKeyPossessionStatement(C509Certificate certificate)
    {
        this(certificate.getIssuer(), certificate.getSerialNumber(), certificate);
    }

    /**
     * A statement naming the signature certificate, optionally carrying it.
     *
     * @param certificate the signature certificate, or null to omit it.
     */
    public C509PrivateKeyPossessionStatement(X500Name issuer, BigInteger serialNumber,
        C509Certificate certificate)
    {
        if (issuer == null || serialNumber == null)
        {
            throw new NullPointerException("issuer and serialNumber are required");
        }
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.certificate = certificate;
    }

    /**
     * Parse a statement from the CBOR encoding of the attribute value (the array).
     */
    public static C509PrivateKeyPossessionStatement getInstance(byte[] cborEncoding)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(cborEncoding);
        C509PrivateKeyPossessionStatement statement = parse(in);
        in.expectEnd();
        return statement;
    }

    static C509PrivateKeyPossessionStatement parse(CBORDecoder in)
        throws IOException
    {
        if (in.readArrayHeader() != 3)
        {
            throw new IOException("C509 PrivateKeyPossessionStatement array must have 3 elements");
        }
        X500Name issuer = C509Name.parse(in).toX500Name();
        BigInteger serialNumber = new BigInteger(1, C509Certificate.readSerialNumber(in));
        C509Certificate certificate = null;
        if (in.nextIsNull())
        {
            in.readNull();
        }
        else if (in.peekMajorType() == CBORType.BYTE_STRING)
        {
            certificate = C509Certificate.getInstance(in.readByteString());
        }
        else
        {
            throw new IOException("C509 PrivateKeyPossessionStatement cert must be C509CertData or null");
        }
        return new C509PrivateKeyPossessionStatement(issuer, serialNumber, certificate);
    }

    /**
     * Build the C509 form of an RFC 9883 statement, re-encoding any certificate it
     * carries as a type 3 C509 certificate.
     *
     * @throws IOException if the issuer name or the certificate cannot be represented in C509.
     */
    public static C509PrivateKeyPossessionStatement fromPrivateKeyPossessionStatement(
        PrivateKeyPossessionStatement statement, C509ConversionOptions options)
        throws IOException
    {
        IssuerAndSerialNumber signer = statement.getSigner();
        C509Certificate certificate = null;
        if (statement.getCert() != null)
        {
            certificate = C509Certificate.fromX509Certificate(statement.getCert(), options);
        }
        C509PrivateKeyPossessionStatement c509 = new C509PrivateKeyPossessionStatement(signer.getName(),
            signer.getCertificateSerialNumber().getValue(), certificate);
        // the name conversion is what can fail; do it now rather than at encoding time
        c509.getEncoded();
        return c509;
    }

    /**
     * Return the RFC 9883 form of this statement.
     *
     * @throws IOException if the certificate carried is natively signed (type 2) and
     *         so has no X.509 form.
     */
    public PrivateKeyPossessionStatement toPrivateKeyPossessionStatement()
        throws IOException
    {
        Certificate cert = null;
        if (certificate != null)
        {
            if (certificate.getCertificateType() != C509Certificate.TYPE_REENCODED_X509)
            {
                throw new IOException(
                    "C509 PrivateKeyPossessionStatement carries a natively signed certificate, which has no X.509 form");
            }
            cert = certificate.toX509Certificate();
        }
        return new PrivateKeyPossessionStatement(new IssuerAndSerialNumber(issuer, serialNumber), cert);
    }

    /**
     * Return the issuer name of the signature certificate.
     */
    public X500Name getIssuer()
    {
        return issuer;
    }

    /**
     * Return the serial number of the signature certificate.
     */
    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

    /**
     * Return the signature certificate, or null if the statement only names it.
     */
    public C509Certificate getCertificate()
    {
        return certificate;
    }

    /**
     * Return the CBOR encoding of the attribute value.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        encodeTo(new CBOREncoder(bOut));
        return bOut.toByteArray();
    }

    void encodeTo(CBOREncoder out)
        throws IOException
    {
        C509Name issuerName;
        try
        {
            issuerName = C509Name.fromX500Name(issuer);
        }
        catch (IllegalArgumentException e)
        {
            throw Exceptions.ioException("PrivateKeyPossessionStatement issuer " + e.getMessage(), e);
        }
        C509Certificate.checkSerialNumber(serialNumber);
        out.writeArrayHeader(3);
        issuerName.encodeTo(out);
        C509Certificate.writeSerialNumber(out, serialNumber);
        if (certificate == null)
        {
            out.writeNull();
        }
        else
        {
            out.writeByteString(certificate.getEncoded());
        }
    }
}
