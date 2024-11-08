package org.bouncycastle.cert;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DeltaCertificateDescriptor;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Validity;

/**
 * General tool for handling the extension described in: https://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/
 */
public class DeltaCertificateTool
{
    public static Extension makeDeltaCertificateExtension(boolean isCritical, Certificate deltaCert)
        throws IOException
    {
        DeltaCertificateDescriptor descriptor = new DeltaCertificateDescriptor(
            deltaCert.getSerialNumber(),
            deltaCert.getSignatureAlgorithm(),
            deltaCert.getIssuer(),
            deltaCert.getValidity(),
            deltaCert.getSubject(),
            deltaCert.getSubjectPublicKeyInfo(),
            deltaCert.getExtensions(),
            deltaCert.getSignature());

        ASN1OctetString extnValue = new DEROctetString(descriptor.getEncoded(ASN1Encoding.DER));

        return new Extension(Extension.deltaCertificateDescriptor, isCritical, extnValue);
    }

    public static Extension makeDeltaCertificateExtension(boolean isCritical, X509CertificateHolder deltaCert)
        throws IOException
    {
        return makeDeltaCertificateExtension(isCritical, deltaCert.toASN1Structure());
    }

    public static Certificate extractDeltaCertificate(TBSCertificate baseTBSCert)
    {
        Extensions baseExtensions = baseTBSCert.getExtensions();

        Extension dcdExtension = baseExtensions.getExtension(Extension.deltaCertificateDescriptor);
        if (dcdExtension == null)
        {
            throw new IllegalStateException("no deltaCertificateDescriptor present");
        }

        DeltaCertificateDescriptor descriptor = DeltaCertificateDescriptor.getInstance(dcdExtension.getParsedValue());

        ASN1Integer version = baseTBSCert.getVersion();
        ASN1Integer serialNumber = descriptor.getSerialNumber();

        AlgorithmIdentifier signature = descriptor.getSignature();
        if (signature == null)
        {
            signature = baseTBSCert.getSignature();
        }

        X500Name issuer = descriptor.getIssuer();
        if (issuer == null)
        {
            issuer = baseTBSCert.getIssuer();
        }

        Validity validity = descriptor.getValidityObject();
        if (validity == null)
        {
            validity = baseTBSCert.getValidity();
        }

        X500Name subject = descriptor.getSubject();
        if (subject == null)
        {
            subject = baseTBSCert.getSubject();
        }

        SubjectPublicKeyInfo subjectPublicKeyInfo = descriptor.getSubjectPublicKeyInfo();

        Extensions extensions = extractDeltaExtensions(descriptor.getExtensions(), baseExtensions);

        // TODO Copy over the issuerUniqueID and/or subjectUniqueID (if the issuer/subject resp. are unmodified)?
        TBSCertificate tbsCertificate = new TBSCertificate(version, serialNumber, signature, issuer, validity, subject,
            subjectPublicKeyInfo, null, null, extensions);

        return new Certificate(tbsCertificate, signature, descriptor.getSignatureValue());
    }

    public static X509CertificateHolder extractDeltaCertificate(X509CertificateHolder baseCert)
    {
        return new X509CertificateHolder(extractDeltaCertificate(baseCert.getTBSCertificate()));
    }

    public static DeltaCertificateDescriptor trimDeltaCertificateDescriptor(DeltaCertificateDescriptor descriptor,
        TBSCertificate tbsCertificate, Extensions tbsExtensions)
    {
        return descriptor.trimTo(tbsCertificate, tbsExtensions);
    }

    private static Extensions extractDeltaExtensions(Extensions descriptorExtensions, Extensions baseExtensions)
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        Enumeration baseEnum = baseExtensions.oids();
        while (baseEnum.hasMoreElements())
        {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)baseEnum.nextElement();
            if (!Extension.deltaCertificateDescriptor.equals(oid))
            {
                extGen.addExtension(baseExtensions.getExtension(oid));
            }
        }

        if (descriptorExtensions != null)
        {
            Enumeration descriptorEnum = descriptorExtensions.oids();
            while (descriptorEnum.hasMoreElements())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)descriptorEnum.nextElement();
                extGen.replaceExtension(descriptorExtensions.getExtension(oid));
            }
        }

        return extGen.isEmpty() ? null : extGen.generate();
    }
}
