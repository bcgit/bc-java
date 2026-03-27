package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
import org.bouncycastle.asn1.cms.OriginatorPublicKey;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.Gost2814789KeyWrapParameters;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.GenericKey;

public abstract class KeyAgreeRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    private final ASN1ObjectIdentifier keyAgreementOID;
    private final ASN1ObjectIdentifier keyEncryptionOID;
    private final SubjectPublicKeyInfo originatorKeyInfo;

    protected KeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID,
        SubjectPublicKeyInfo originatorKeyInfo, ASN1ObjectIdentifier keyEncryptionOID)
    {
        this.originatorKeyInfo = originatorKeyInfo;
        this.keyAgreementOID = keyAgreementOID;
        this.keyEncryptionOID = keyEncryptionOID;
    }

    public RecipientInfo generate(GenericKey contentEncryptionKey) throws CMSException
    {
        OriginatorPublicKey originatorPublicKey = createOriginatorPublicKey(originatorKeyInfo); 
        OriginatorIdentifierOrKey originator = new OriginatorIdentifierOrKey(originatorPublicKey);

        ASN1Encodable keyEncAlgParams = null;
        if (CMSUtils.isDES(keyEncryptionOID) || PKCSObjectIdentifiers.id_alg_CMSRC2wrap.equals(keyEncryptionOID))
        {
            keyEncAlgParams = DERNull.INSTANCE;
        }
        else if (CMSUtils.isGOST(keyAgreementOID))
        {
            keyEncAlgParams = new Gost2814789KeyWrapParameters(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet);
        }

        AlgorithmIdentifier keyEncAlgorithm = new AlgorithmIdentifier(keyEncryptionOID, keyEncAlgParams);
        AlgorithmIdentifier keyAgreeAlgorithm = new AlgorithmIdentifier(keyAgreementOID, keyEncAlgorithm);

        ASN1Sequence recipients = generateRecipientEncryptedKeys(keyAgreeAlgorithm, keyEncAlgorithm, contentEncryptionKey);

        ASN1OctetString ukm = DEROctetString.fromContentsOptional(getUserKeyingMaterial(keyAgreeAlgorithm));

        return new RecipientInfo(new KeyAgreeRecipientInfo(originator, ukm, keyAgreeAlgorithm, recipients));
    }

    protected OriginatorPublicKey createOriginatorPublicKey(SubjectPublicKeyInfo originatorKeyInfo)
    {
        return new OriginatorPublicKey(originatorKeyInfo.getAlgorithm(), originatorKeyInfo.getPublicKeyData());
    }

    protected abstract ASN1Sequence generateRecipientEncryptedKeys(AlgorithmIdentifier keyAgreeAlgorithm,
        AlgorithmIdentifier keyEncAlgorithm, GenericKey contentEncryptionKey) throws CMSException;

    protected abstract byte[] getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlgorithm) throws CMSException;
}
