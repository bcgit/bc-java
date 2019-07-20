package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * <pre>
 *     EncryptedPrivateKeyObjectData ::= SEQUENCE {
 *         encryptedPrivateKeyInfo EncryptedPrivateKeyInfo,
 *         certificates SEQUENCE OF Certificate
 *     }
 * </pre>
 */
public class EncryptedPrivateKeyData
    extends ASN1Object
{
    private final EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
    private final Certificate[] certificateChain;

    public EncryptedPrivateKeyData(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, Certificate[] certificateChain)
    {
        this.encryptedPrivateKeyInfo = encryptedPrivateKeyInfo;
        this.certificateChain = new Certificate[certificateChain.length];
        System.arraycopy(certificateChain, 0, this.certificateChain, 0, certificateChain.length);
    }

    private EncryptedPrivateKeyData(ASN1Sequence seq)
    {
        encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.getInstance(seq.getObjectAt(0));
        ASN1Sequence certSeq = ASN1Sequence.getInstance(seq.getObjectAt(1));
        certificateChain = new Certificate[certSeq.size()];
        for (int i = 0; i != certificateChain.length; i++)
        {
            certificateChain[i] = Certificate.getInstance(certSeq.getObjectAt(i));
        }
    }

    public static EncryptedPrivateKeyData getInstance(Object o)
    {
        if (o instanceof EncryptedPrivateKeyData)
        {
            return (EncryptedPrivateKeyData)o;
        }
        else if (o != null)
        {
            return new EncryptedPrivateKeyData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Certificate[] getCertificateChain()
    {
        Certificate[] tmp = new Certificate[certificateChain.length];

        System.arraycopy(certificateChain, 0, tmp, 0, certificateChain.length);

        return tmp;
    }

    public EncryptedPrivateKeyInfo getEncryptedPrivateKeyInfo()
    {
        return encryptedPrivateKeyInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(encryptedPrivateKeyInfo);
        v.add(new DERSequence(certificateChain));

        return new DERSequence(v);
    }
}
