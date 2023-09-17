package org.bouncycastle.cert;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;

/**
 * General tool for handling the extension described in: https://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/
 */
public class DeltaCertificateTool
{
    public static Extension makeDeltaCertificateExtension(boolean isCritical, X509CertificateHolder deltaCert)
        throws IOException
    {
        ASN1EncodableVector deltaV = new ASN1EncodableVector();

        deltaV.add(new ASN1Integer(deltaCert.getSerialNumber()));
        deltaV.add(new DERTaggedObject(false, 0, deltaCert.getSignatureAlgorithm()));
        deltaV.add(new DERTaggedObject(false, 1, deltaCert.getIssuer()));

        ASN1EncodableVector validity = new ASN1EncodableVector(2);
        validity.add(deltaCert.toASN1Structure().getStartDate());
        validity.add(deltaCert.toASN1Structure().getEndDate());

        deltaV.add(new DERTaggedObject(false, 2, new DERSequence(validity)));
        deltaV.add(new DERTaggedObject(false, 3, deltaCert.getSubject()));
        deltaV.add(deltaCert.getSubjectPublicKeyInfo());
        if (deltaCert.getExtensions() != null)
        {
            deltaV.add(new DERTaggedObject(false, 4, deltaCert.getExtensions()));
        }
        deltaV.add(new DERBitString(deltaCert.getSignature()));

        return new Extension(Extension.deltaCertificateDescriptor, isCritical, new DERSequence(deltaV).getEncoded(ASN1Encoding.DER));
    }

    public static X509CertificateHolder extractDeltaCertificate(X509CertificateHolder originCert)
    {
        ASN1ObjectIdentifier deltaExtOid = Extension.deltaCertificateDescriptor;
        Extension deltaExt = originCert.getExtension(deltaExtOid);

        ASN1Sequence seq = ASN1Sequence.getInstance(deltaExt.getParsedValue());
//        *      version          [ 0 ]  Version DEFAULT v1(0),
//        *      serialNumber            CertificateSerialNumber,
//        *      signature               AlgorithmIdentifier,
//        *      issuer                  Name,
//        *      validity                Validity,
//        *      subject                 Name,
//        *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
//        *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
//        *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
//        *      extensions        [ 3 ] Extensions OPTIONAL
        ASN1Sequence originTbs = ASN1Sequence.getInstance(originCert.toASN1Structure().getTBSCertificate().toASN1Primitive());
        int idx = 0;
        ASN1Encodable[] extracted = originTbs.toArray();

        extracted[0] = originTbs.getObjectAt(0);
        extracted[1] = ASN1Integer.getInstance(seq.getObjectAt(idx++));

        ASN1Encodable next = seq.getObjectAt(idx++);
        while (next instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(next);
            switch (tagged.getTagNo())
            {
            case 0:
                extracted[2] = ASN1Sequence.getInstance(tagged, false);
                break;
            case 1:
                extracted[3] = ASN1Sequence.getInstance(tagged, true);   // issuer
                break;
            case 2:
                extracted[4] = ASN1Sequence.getInstance(tagged, false);
                break;
            case 3:
                extracted[5] = ASN1Sequence.getInstance((ASN1TaggedObject)next, true);   // subject
                break;
            }
            next = seq.getObjectAt(idx++);
        }

        extracted[6] = next;  // subjectPublicKey

        if (extracted[2] == null)
        {
            extracted[2] = originTbs.getObjectAt(2);
        }

        if (extracted[3] == null)
        {
            extracted[3] = originTbs.getObjectAt(3);
        }

        if (extracted[4] == null)
        {
            extracted[4] = originTbs.getObjectAt(4);
        }

        if (extracted[5] == null)
        {
            extracted[5] = originTbs.getObjectAt(5);
        }

        ExtensionsGenerator extGen = extractExtensions(originTbs);

        if (idx < (seq.size() - 1))  // last element is the signature
        {
            next = seq.getObjectAt(idx++);
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(next);
            if (tagged.getTagNo() != 4)
            {
                throw new IllegalArgumentException("malformed delta extension");
            }

            ASN1Sequence deltaExts = ASN1Sequence.getInstance(tagged, false);

            for (int i = 0; i != deltaExts.size(); i++)
            {
                Extension ext = Extension.getInstance(deltaExts.getObjectAt(i));

                extGen.replaceExtension(ext);
            }

            extracted[7] = new DERTaggedObject(3, extGen.generate());
        }
        else
        {
            if (!extGen.isEmpty())
            {
                extracted[7] = new DERTaggedObject(3, extGen.generate());
            }
            else
            {
                extracted[7] = null;
            }
        }

        ASN1EncodableVector tbsDeltaCertV = new ASN1EncodableVector(7);
        for (int i = 0; i != extracted.length; i++)
        {
            if (extracted[i] != null)
            {
                tbsDeltaCertV.add(extracted[i]);
            }
        }

        ASN1EncodableVector certV = new ASN1EncodableVector();
        certV.add(new DERSequence(tbsDeltaCertV));
        certV.add(ASN1Sequence.getInstance(extracted[2]));
        certV.add(ASN1BitString.getInstance(seq.getObjectAt(seq.size() - 1)));

        return new X509CertificateHolder(Certificate.getInstance(new DERSequence(certV)));
    }

    private static ExtensionsGenerator extractExtensions(ASN1Sequence originTbs)
    {
        ASN1ObjectIdentifier deltaExtOid = Extension.deltaCertificateDescriptor;
        ASN1Sequence originExt = ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(originTbs.getObjectAt(originTbs.size() - 1)), true);
        ExtensionsGenerator extGen = new ExtensionsGenerator();

        for (int i = 0; i != originExt.size(); i++)
        {
            Extension ext = Extension.getInstance(originExt.getObjectAt(i));
            if (!deltaExtOid.equals(ext.getExtnId()))
            {
                extGen.addExtension(ext);
            }
        }

        return extGen;
    }
}
