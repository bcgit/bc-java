package org.bouncycastle.pkcs;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.operator.ContentVerifierProvider;

public class DeltaCertAttributeUtils
{
    public static Extension makeDeltaCertificateExtension(DeltaCertificateRequestAttributeValue deltaReqAttr)
        throws IOException
    {
         return null;
    }

    public static boolean isDeltaRequestSignatureValid(PKCS10CertificationRequest baseRequest, ContentVerifierProvider contentVerifierProvider)
        throws PKCSException
    {
        Attribute[] attributes = baseRequest.getAttributes(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.2"));

        DeltaCertificateRequestAttributeValue deltaReq = new DeltaCertificateRequestAttributeValue(attributes[0]);

        attributes = baseRequest.getAttributes(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.3"));

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

            if (!attr.getAttrType().equals(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.3")))
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
}
