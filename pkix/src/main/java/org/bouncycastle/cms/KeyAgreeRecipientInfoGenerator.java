package org.bouncycastle.cms;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
import org.bouncycastle.asn1.cms.OriginatorPublicKey;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.GenericKey;

public abstract class KeyAgreeRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    private ASN1ObjectIdentifier keyAgreementOID;
    private ASN1ObjectIdentifier keyEncryptionOID;
    private SubjectPublicKeyInfo originatorKeyInfo;

    protected KeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, SubjectPublicKeyInfo originatorKeyInfo, ASN1ObjectIdentifier keyEncryptionOID)
    {
        this.originatorKeyInfo = originatorKeyInfo;
        this.keyAgreementOID = keyAgreementOID;
        this.keyEncryptionOID = keyEncryptionOID;
    }

    public RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException
    {
        OriginatorIdentifierOrKey originator = new OriginatorIdentifierOrKey(
                createOriginatorPublicKey(originatorKeyInfo));

        AlgorithmIdentifier keyEncAlg;
        if (CMSUtils.isDES(keyEncryptionOID.getId()) || keyEncryptionOID.equals(PKCSObjectIdentifiers.id_alg_CMSRC2wrap))
        {
            keyEncAlg = new AlgorithmIdentifier(keyEncryptionOID, DERNull.INSTANCE);
        }
        else
        {
            keyEncAlg = new AlgorithmIdentifier(keyEncryptionOID);
        }

        AlgorithmIdentifier keyAgreeAlg = new AlgorithmIdentifier(keyAgreementOID, keyEncAlg);

        ASN1Sequence recipients = generateRecipientEncryptedKeys(keyAgreeAlg, keyEncAlg, contentEncryptionKey);
        ASN1Encodable userKeyingMaterial = getUserKeyingMaterial(keyAgreeAlg);

        if (userKeyingMaterial != null)
        {
            try
            {
                return new RecipientInfo(new KeyAgreeRecipientInfo(originator, new DEROctetString(userKeyingMaterial),
                    keyAgreeAlg, recipients));
            }
            catch (IOException e)
            {
                throw new CMSException("unable to encode userKeyingMaterial: " + e.getMessage(), e);
            }
        }
        else
        {
            return new RecipientInfo(new KeyAgreeRecipientInfo(originator, null,
                keyAgreeAlg, recipients));
        }
    }

    protected OriginatorPublicKey createOriginatorPublicKey(SubjectPublicKeyInfo originatorKeyInfo)
    {
        return new OriginatorPublicKey(
            new AlgorithmIdentifier(originatorKeyInfo.getAlgorithm().getAlgorithm(), DERNull.INSTANCE),
            originatorKeyInfo.getPublicKeyData().getBytes());
    }

    protected abstract ASN1Sequence generateRecipientEncryptedKeys(AlgorithmIdentifier keyAgreeAlgorithm, AlgorithmIdentifier keyEncAlgorithm, GenericKey contentEncryptionKey)
        throws CMSException;

    protected abstract ASN1Encodable getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlgorithm)
        throws CMSException;

}