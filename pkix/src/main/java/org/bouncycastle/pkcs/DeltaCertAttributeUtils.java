package org.bouncycastle.pkcs;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.operator.ContentVerifierProvider;

public class DeltaCertAttributeUtils
{
    static final ASN1ObjectIdentifier deltaCertificateRequestSignature = new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.3");

    public static boolean isDeltaRequestSignatureValid(PKCS10CertificationRequest baseRequest, ContentVerifierProvider contentVerifierProvider)
        throws PKCSException
    {
        Attribute[] attributes = baseRequest.getAttributes(DeltaCertificateRequestAttributeValueBuilder.deltaCertificateRequest);

        DeltaCertificateRequestAttributeValue deltaReq = new DeltaCertificateRequestAttributeValue(attributes[0]);

        attributes = baseRequest.getAttributes(deltaCertificateRequestSignature);

        CertificationRequest deltaPkcs10 = baseRequest.toASN1Structure();
        CertificationRequestInfo deltaInfo = deltaPkcs10.getCertificationRequestInfo();

        ASN1EncodableVector deltaPkcs10InfoV = new ASN1EncodableVector();
        deltaPkcs10InfoV.add(deltaInfo.getVersion());
        deltaPkcs10InfoV.add(deltaInfo.getSubject());
        deltaPkcs10InfoV.add(deltaInfo.getSubjectPublicKeyInfo());

        ASN1EncodableVector attrSetV = new ASN1EncodableVector();
        for (Enumeration en = deltaInfo.getAttributes().getObjects(); en.hasMoreElements();)
        {
            Attribute attr = Attribute.getInstance(en.nextElement());

            if (!attr.getAttrType().equals(deltaCertificateRequestSignature))
            {
                attrSetV.add(attr);
            }
        }

        deltaPkcs10InfoV.add(new DERTaggedObject(false, 0, new DERSet(attrSetV)));

        ASN1EncodableVector deltaPkcs10V = new ASN1EncodableVector();

        deltaPkcs10V.add(new DERSequence(deltaPkcs10InfoV));
        deltaPkcs10V.add(deltaReq.getSignatureAlgorithm());
        deltaPkcs10V.add(attributes[0].getAttributeValues()[0]);

        PKCS10CertificationRequest deltaPkcs10Req = new PKCS10CertificationRequest(CertificationRequest.getInstance(new DERSequence(deltaPkcs10V)));

        return deltaPkcs10Req.isSignatureValid(contentVerifierProvider);
    }

    /**
     * Return a copy of {@code delta} with subject, signatureAlgorithm and extensions
     * fields stripped when they match the corresponding fields of {@code baseRequest}.
     * <p>
     * Mirrors the cert-side rule in
     * {@link org.bouncycastle.cert.DeltaCertificateTool#trimDeltaCertificateDescriptor}:
     * draft-bonnell-lamps-chameleon-certs §4.1 says the extensions field MUST NOT contain
     * any extension which has the same criticality and DER-encoded value as the base,
     * whose type does not appear in the base, or which is the DCD extension type itself.
     * </p>
     */
    public static DeltaCertificateRequestAttributeValue trimDeltaCertificateRequest(
        DeltaCertificateRequestAttributeValue delta, PKCS10CertificationRequest baseRequest)
    {
        DeltaCertificateRequestAttributeValueBuilder builder = new DeltaCertificateRequestAttributeValueBuilder(
            delta.getSubjectPKInfo());

        X500Name subject = delta.getSubject();
        if (subject != null && !subject.equals(baseRequest.getSubject()))
        {
            builder.setSubject(subject);
        }

        AlgorithmIdentifier signatureAlgorithm = delta.getSignatureAlgorithm();
        if (signatureAlgorithm != null && !signatureAlgorithm.equals(baseRequest.getSignatureAlgorithm()))
        {
            builder.setSignatureAlgorithm(signatureAlgorithm);
        }

        Extensions extensions = delta.getExtensions();
        if (extensions != null)
        {
            // getRequestedExtensions parses the extensionRequest attribute, so only ask for
            // it once we know there are delta extensions to diff against.
            Extensions baseExtensions = baseRequest.getRequestedExtensions();
            if (baseExtensions != null)
            {
                ExtensionsGenerator generator = new ExtensionsGenerator();

                for (Enumeration en = baseExtensions.oids(); en.hasMoreElements();)
                {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)en.nextElement();
                    if (DeltaCertificateRequestAttributeValueBuilder.deltaCertificateRequest.equals(oid))
                    {
                        continue;
                    }

                    Extension deltaExt = extensions.getExtension(oid);
                    if (deltaExt != null && !deltaExt.equals(baseExtensions.getExtension(oid)))
                    {
                        generator.addExtension(deltaExt);
                    }
                }

                if (!generator.isEmpty())
                {
                    builder.setExtensions(generator.generate());
                }
            }
            else
            {
                // A delta extension may only replace an extension already present in the base
                // request: §4.1 forbids the extensions field from carrying an extension whose
                // type does not appear in the base. With no base extensions there is nothing
                // to replace, so every delta extension is dropped.
            }
        }

        return builder.build();
    }
}
