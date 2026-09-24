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
        try
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
        finally
        {
            generationComplete();
        }
    }

    protected OriginatorPublicKey createOriginatorPublicKey(SubjectPublicKeyInfo originatorKeyInfo)
    {
        return new OriginatorPublicKey(originatorKeyInfo.getAlgorithm(), originatorKeyInfo.getPublicKeyData());
    }

    protected boolean isEC(ASN1ObjectIdentifier algorithmOID)
    {
        return CMSUtils.isEC(algorithmOID);
    }

    protected boolean isHKDF(ASN1ObjectIdentifier algorithmOID)
    {
        return CMSUtils.isHKDF(algorithmOID);
    }

    protected boolean isMQV(ASN1ObjectIdentifier algorithmOID)
    {
        return CMSUtils.isMQV(algorithmOID);
    }

    protected boolean isRFC2631(ASN1ObjectIdentifier algorithmOID)
    {
        return CMSUtils.isRFC2631(algorithmOID);
    }

    protected boolean isGOST(ASN1ObjectIdentifier algorithmOID)
    {
        return CMSUtils.isGOST(algorithmOID);
    }

    protected abstract ASN1Sequence generateRecipientEncryptedKeys(AlgorithmIdentifier keyAgreeAlgorithm,
        AlgorithmIdentifier keyEncAlgorithm, GenericKey contentEncryptionKey) throws CMSException;

    protected abstract byte[] getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlgorithm) throws CMSException;

    /**
     * Called at the end of every {@link #generate(GenericKey)}, whether it completed normally or not, so a
     * subclass can release any state it holds for the duration of a single KeyAgreeRecipientInfo (e.g. an
     * ephemeral key pair). The default implementation does nothing.
     * <p>
     * This is called from a finally block, so an implementation must not throw: an exception thrown here would
     * replace the result, or the exception, of the generate call.
     * </p>
     */
    protected void generationComplete()
    {
    }
}
