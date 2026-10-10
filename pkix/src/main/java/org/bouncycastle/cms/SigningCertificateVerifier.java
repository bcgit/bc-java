package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;

/**
 * Checks of the ESS signing-certificate attributes (RFC 2634 sec. 5.4, RFC 5035 sec. 3), which bind the certificate
 * a signature is verified with into the signed attributes. CAdES requires one of them (RFC 5126 sec. 5.7.3); plain
 * CMS does not.
 * <p>
 * A signature value on its own does not commit to the key that verifies it, so anything covering only the value, such
 * as a CAdES signature time-stamp or a CMS countersignature, covers the signer's certificate and the content only
 * when the signed attributes carry the certificate's hash and that hash is checked against the certificate the
 * signature verified under. {@link #verifySigningCertificate(SignerInformation, X509CertificateHolder,
 * DigestCalculatorProvider)} is that check.
 */
public final class SigningCertificateVerifier
{
    private SigningCertificateVerifier()
    {
    }

    /**
     * Return the certificate identifiers the signer's signed attributes carry: the first ESSCertID of a
     * signing-certificate attribute, as an ESSCertIDv2 naming SHA-1, and the first ESSCertIDv2 of a
     * signing-certificate-v2 attribute. Both may be present, and RFC 5035 has them evaluated independently.
     *
     * @param signer the signer to inspect.
     * @return the identifiers found, empty when the signer carries neither attribute.
     * @throws CMSException if an attribute is present but malformed or empty, or appears only among the unsigned
     * attributes, where RFC 5035 sec. 3 forbids it.
     */
    public static ESSCertIDv2[] getSigningCertificateIDs(SignerInformation signer)
        throws CMSException
    {
        AttributeTable signed = signer.getSignedAttributes();
        ESSCertIDv2 v1 = null;
        ESSCertIDv2 v2 = null;

        if (signed != null)
        {
            try
            {
                Attribute attr = signed.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
                if (attr != null)
                {
                    SigningCertificate sc = SigningCertificate.getInstance(singleValue(attr, "signing-certificate"));
                    if (sc.getCerts().length == 0)
                    {
                        throw new CMSException("signing-certificate attribute carries no ESSCertID");
                    }
                    v1 = ESSCertIDv2.from(sc.getCerts()[0]);
                }

                attr = signed.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
                if (attr != null)
                {
                    SigningCertificateV2 sc = SigningCertificateV2.getInstance(singleValue(attr, "signing-certificate-v2"));
                    if (sc.getCerts().length == 0)
                    {
                        throw new CMSException("signing-certificate-v2 attribute carries no ESSCertIDv2");
                    }
                    v2 = sc.getCerts()[0];
                }
            }
            catch (IllegalArgumentException e)
            {
                throw new CMSException("malformed signing-certificate attribute: " + e.getMessage(), e);
            }
        }

        if (v1 == null && v2 == null)
        {
            AttributeTable unsigned = signer.getUnsignedAttributes();
            if (unsigned != null && (unsigned.hasAny(PKCSObjectIdentifiers.id_aa_signingCertificate)
                || unsigned.hasAny(PKCSObjectIdentifiers.id_aa_signingCertificateV2)))
            {
                throw new CMSException("signing-certificate attribute must be a signed attribute");
            }
            return new ESSCertIDv2[0];
        }
        if (v1 != null && v2 != null)
        {
            return new ESSCertIDv2[]{ v1, v2 };
        }
        return new ESSCertIDv2[]{ v1 != null ? v1 : v2 };
    }

    /**
     * Check that the signer's signed attributes identify the given certificate: a signing-certificate or
     * signing-certificate-v2 attribute must be present, each identifier's hash must be the digest of the
     * certificate's encoding under the algorithm it names, and an issuerSerial, when present, must match the
     * certificate's issuer and serial number. The certificate should be the one the signature was verified with.
     *
     * @param signer      the signer to check.
     * @param cert        the certificate the signature verifies under.
     * @param digCalcProv source of digest calculators for the certificate hash.
     * @throws CMSException if the attribute is absent, malformed or in the wrong place, names a digest that is not
     * acceptable or cannot be calculated, or does not identify the certificate.
     */
    public static void verifySigningCertificate(SignerInformation signer, X509CertificateHolder cert,
                                                DigestCalculatorProvider digCalcProv)
        throws CMSException
    {
        ESSCertIDv2[] ids = getSigningCertificateIDs(signer);
        if (ids.length == 0)
        {
            throw new CMSException("no signing-certificate attribute in signed attributes");
        }

        byte[] encoded;
        try
        {
            encoded = cert.getEncoded();
        }
        catch (IOException e)
        {
            throw new CMSException("unable to encode certificate: " + e.getMessage(), e);
        }

        for (int i = 0; i != ids.length; i++)
        {
            ESSCertIDv2 id = ids[i];
            AlgorithmIdentifier hashAlg = id.getHashAlgorithm();
            ASN1ObjectIdentifier hashOid = hashAlg.getAlgorithm();

            if (PKCSObjectIdentifiers.md5.equals(hashOid) || PKCSObjectIdentifiers.md4.equals(hashOid)
                || PKCSObjectIdentifiers.md2.equals(hashOid))
            {
                throw new CMSException("signing-certificate hash algorithm not acceptable: " + hashOid);
            }

            byte[] digest;
            try
            {
                DigestCalculator calc = digCalcProv.get(hashAlg);
                OutputStream out = calc.getOutputStream();
                out.write(encoded);
                out.close();
                digest = calc.getDigest();
            }
            catch (OperatorCreationException e)
            {
                throw new CMSException("unable to calculate signing-certificate hash: " + e.getMessage(), e);
            }
            catch (IOException e)
            {
                throw new CMSException("unable to calculate signing-certificate hash: " + e.getMessage(), e);
            }

            if (!Arrays.constantTimeAreEqual(id.getCertHashObject().getOctets(), digest))
            {
                throw new CMSException("signing-certificate hash does not match the certificate");
            }

            IssuerSerial issuerSerial = id.getIssuerSerial();
            if (issuerSerial != null)
            {
                if (!issuerSerial.getSerial().getValue().equals(cert.getSerialNumber()))
                {
                    throw new CMSException("signing-certificate serial number does not match the certificate");
                }

                GeneralName[] names = issuerSerial.getIssuer().getNames();
                boolean found = false;
                for (int j = 0; j != names.length; j++)
                {
                    if (names[j].getTagNo() == GeneralName.directoryName
                        && X500Name.getInstance(names[j].getName()).equals(cert.getIssuer()))
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    throw new CMSException("signing-certificate issuer does not match the certificate");
                }
            }
        }
    }

    private static Object singleValue(Attribute attr, String name)
        throws CMSException
    {
        if (attr.getAttrValues().size() != 1)
        {
            throw new CMSException(name + " attribute must have exactly one value");
        }
        return attr.getAttrValues().getObjectAt(0);
    }
}
