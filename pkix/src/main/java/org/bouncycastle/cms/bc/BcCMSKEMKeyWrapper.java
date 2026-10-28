package org.bouncycastle.cms.bc;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.CMSORIforKEMOtherInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.KEMKeyWrapper;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.util.Arrays;

/**
 * RFC 9629 KEMRecipientInfo key wrapper over the light-weight API: ML-KEM encapsulation, the KDF of
 * the recipient info (KDF3 with SHA-256 by default), and AES key wrap of the content-encryption key.
 */
class BcCMSKEMKeyWrapper
    extends KEMKeyWrapper
{
    private final AsymmetricKeyParameter publicKey;
    private final AlgorithmIdentifier symWrapAlgorithm;
    private final int kekLength;

    private SecureRandom random;
    private AlgorithmIdentifier kdfAlgorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3,
        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
    private byte[] encapsulation;
    private byte[] ukm;

    BcCMSKEMKeyWrapper(SubjectPublicKeyInfo publicKeyInfo, ASN1ObjectIdentifier symWrapAlg)
        throws IOException
    {
        this(publicKeyInfo.getAlgorithm(), PublicKeyFactory.createKey(publicKeyInfo), symWrapAlg);
    }

    BcCMSKEMKeyWrapper(AsymmetricKeyParameter publicKey, ASN1ObjectIdentifier symWrapAlg)
        throws IOException
    {
        this(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey).getAlgorithm(), publicKey, symWrapAlg);
    }

    private BcCMSKEMKeyWrapper(AlgorithmIdentifier kemAlgorithm, AsymmetricKeyParameter publicKey, ASN1ObjectIdentifier symWrapAlg)
    {
        super(kemAlgorithm);

        if (!(publicKey instanceof MLKEMPublicKeyParameters))
        {
            throw new IllegalArgumentException("KEM recipient key must be an ML-KEM public key");
        }

        this.publicKey = publicKey;
        this.symWrapAlgorithm = new AlgorithmIdentifier(symWrapAlg);
        this.kekLength = BcKEMUtil.getKekSize(symWrapAlg);
    }

    BcCMSKEMKeyWrapper setKDF(AlgorithmIdentifier kdfAlgorithm)
    {
        this.kdfAlgorithm = kdfAlgorithm;

        return this;
    }

    BcCMSKEMKeyWrapper setUKM(byte[] ukm)
    {
        this.ukm = Arrays.clone(ukm);

        return this;
    }

    BcCMSKEMKeyWrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }

    public AlgorithmIdentifier getKdfAlgorithmIdentifier()
    {
        return kdfAlgorithm;
    }

    public int getKekLength()
    {
        return kekLength;
    }

    public AlgorithmIdentifier getWrapAlgorithmIdentifier()
    {
        return symWrapAlgorithm;
    }

    public byte[] getUkm()
    {
        return Arrays.clone(ukm);
    }

    public byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException
    {
        byte[] kek = null;
        try
        {
            byte[] oriInfoEnc = new CMSORIforKEMOtherInfo(symWrapAlgorithm, kekLength, ukm).getEncoded();

            SecretWithEncapsulation secEnc = new MLKEMGenerator(random).generateEncapsulated(publicKey);

            encapsulation = secEnc.getEncapsulation();
            kek = BcKEMUtil.deriveKek(kdfAlgorithm, secEnc.getSecret(), oriInfoEnc, kekLength);

            byte[] contentEncryptionKey = ((KeyParameter)CMSUtils.getBcKey(encryptionKey)).getKey();

            Wrapper wrapper = BcKEMUtil.createWrapper(symWrapAlgorithm.getAlgorithm());

            wrapper.init(true, new KeyParameter(kek));

            return wrapper.wrap(contentEncryptionKey, 0, contentEncryptionKey.length);
        }
        catch (Exception e)
        {
            throw new OperatorException("unable to wrap contents key: " + e.getMessage(), e);
        }
        finally
        {
            if (kek != null)
            {
                Arrays.clear(kek);
            }
        }
    }
}
