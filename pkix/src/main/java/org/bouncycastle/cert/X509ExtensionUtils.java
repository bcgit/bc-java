package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.DigestCalculator;

/**
 * General utility class for creating calculated extensions using the standard methods.
 * <p>
 * <b>Note:</b> This class is not thread safe!
 * </p>
 */
public class X509ExtensionUtils
{
    private DigestCalculator calculator;

    /**
     * Base constructor - for conformance to RFC 5280 use a calculator based on SHA-1.
     *
     * @param calculator  a calculator for calculating subject key ids.
     */
    public X509ExtensionUtils(DigestCalculator calculator)
    {
        this.calculator = calculator;
    }

    /**
     * Create an AuthorityKeyIdentifier from the passed in arguments.
     *
     * @param certHolder the issuer certificate that the AuthorityKeyIdentifier should refer to.
     * @return an AuthorityKeyIdentifier.
     */
    public AuthorityKeyIdentifier createAuthorityKeyIdentifier(
        X509CertificateHolder certHolder)
    {
        GeneralName             genName = new GeneralName(certHolder.getIssuer());

        return new AuthorityKeyIdentifier(
                getSubjectKeyIdentifier(certHolder), new GeneralNames(genName), certHolder.getSerialNumber());
    }

    /**
     * Create an AuthorityKeyIdentifier from the passed in SubjectPublicKeyInfo.
     *
     * @param publicKeyInfo the SubjectPublicKeyInfo to base the key identifier on.
     * @return an AuthorityKeyIdentifier.
     */
    public AuthorityKeyIdentifier createAuthorityKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo)
    {
        return new AuthorityKeyIdentifier(calculateIdentifier(publicKeyInfo));
    }

    /**
     * Create an AuthorityKeyIdentifier from the passed in arguments.
     *
     * @param publicKeyInfo the SubjectPublicKeyInfo to base the key identifier on.
     * @param generalNames the general names to associate with the issuer cert's issuer.
     * @param serial the serial number of the issuer cert.
     * @return an AuthorityKeyIdentifier.
     */
    public AuthorityKeyIdentifier createAuthorityKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo, GeneralNames generalNames, BigInteger serial)
    {
        return new AuthorityKeyIdentifier(calculateIdentifier(publicKeyInfo), generalNames, serial);
    }

    /**
     * Return a RFC 5280 type 1 key identifier. As in:
     * <pre>
     * (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
     * value of the BIT STRING subjectPublicKey (excluding the tag,
     * length, and number of unused bits).
     * </pre>
     * @param publicKeyInfo the key info object containing the subjectPublicKey field.
     * @return the key identifier.
     */
    public SubjectKeyIdentifier createSubjectKeyIdentifier(
        SubjectPublicKeyInfo publicKeyInfo)
    {
        return new SubjectKeyIdentifier(calculateIdentifier(publicKeyInfo));
    }

    /**
     * Return a RFC 5280 type 2 key identifier. As in:
     * <pre>
     * (2) The keyIdentifier is composed of a four bit type field with
     * the value 0100 followed by the least significant 60 bits of the
     * SHA-1 hash of the value of the BIT STRING subjectPublicKey.
     * </pre>
     * @param publicKeyInfo the key info object containing the subjectPublicKey field.
     * @return the key identifier.
     */
    public SubjectKeyIdentifier createTruncatedSubjectKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo)
    {
        byte[] digest = calculateIdentifier(publicKeyInfo);
        byte[] id = new byte[8];

        System.arraycopy(digest, digest.length - 8, id, 0, id.length);

        id[0] &= 0x0f;
        id[0] |= 0x40;

        return new SubjectKeyIdentifier(id);
    }

    private byte[] getSubjectKeyIdentifier(X509CertificateHolder certHolder)
    {
        if (certHolder.getVersionNumber() != 3)
        {
            return calculateIdentifier(certHolder.getSubjectPublicKeyInfo());
        }
        else
        {
            Extension ext = certHolder.getExtension(Extension.subjectKeyIdentifier);

            if (ext != null)
            {
                return ASN1OctetString.getInstance(ext.getParsedValue()).getOctets();
            }
            else
            {
                return calculateIdentifier(certHolder.getSubjectPublicKeyInfo());
            }
        }
    }

    private byte[] calculateIdentifier(SubjectPublicKeyInfo publicKeyInfo)
    {
        byte[] bytes = publicKeyInfo.getPublicKeyData().getBytes();

        OutputStream cOut = calculator.getOutputStream();

        try
        {
            cOut.write(bytes);

            cOut.close();
        }
        catch (IOException e)
        {   // it's hard to imagine this happening, but yes it does!
            throw new CertRuntimeException("unable to calculate identifier: " + e.getMessage(), e);
        }

        return calculator.getDigest();
    }
}
