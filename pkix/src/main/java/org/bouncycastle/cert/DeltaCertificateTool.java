package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;

public class DeltaCertificateTool
{
    public static X509CertificateHolder extractDeltaCertificate(X509CertificateHolder originCert)
    {
        ASN1ObjectIdentifier deltaExtOid = new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.1");
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

        if (idx != seq.size() - 1)
        {
            next = seq.getObjectAt(idx++);
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(next);
            if (tagged.getTagNo() != 4)
            {
                throw new IllegalArgumentException("malformed delta extension");
            }

            ASN1Sequence deltaExts = ASN1Sequence.getInstance(tagged, false);

            ExtensionsGenerator extGen = new ExtensionsGenerator();

            ASN1Sequence originExt = ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(originTbs.getObjectAt(originTbs.size() - 1)), true);

            for (int i = 0; i != originExt.size(); i++)
            {
                Extension ext = Extension.getInstance(originExt.getObjectAt(i));
                if (!deltaExtOid.equals(ext.getExtnId()))
                {
                    extGen.addExtension(ext);
                }
            }


            for (int i = 0; i != deltaExts.size(); i++)
            {
                extGen.replaceExtension(Extension.getInstance(deltaExts.getObjectAt(i)));
            }

            extracted[7] = new DERTaggedObject(3, extGen.generate());
        }

        ASN1EncodableVector certV = new ASN1EncodableVector();
        certV.add(new DERSequence(extracted));
        certV.add(ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1)), false));
        certV.add(ASN1BitString.getInstance(seq.getObjectAt(idx)));

        return new X509CertificateHolder(Certificate.getInstance(new DERSequence(certV)));
    }
}
