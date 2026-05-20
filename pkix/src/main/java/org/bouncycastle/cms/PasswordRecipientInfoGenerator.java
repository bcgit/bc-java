package org.bouncycastle.cms;

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.util.Arrays;

public abstract class PasswordRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    protected char[] password;

    private AlgorithmIdentifier keyDerivationAlgorithm;
    private ASN1ObjectIdentifier kekAlgorithm;
    private SecureRandom random;
    private int schemeID;
    private int keySize;
    private int blockSize;
    private PasswordRecipient.PRF prf;
    private byte[] salt;
    private int iterationCount;

    protected PasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password)
    {
        this(kekAlgorithm, password, getKeySize(kekAlgorithm), ((Integer)PasswordRecipientInformation.BLOCKSIZES.get(kekAlgorithm)).intValue());
    }

    protected PasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password, int keySize, int blockSize)
    {
        this.password = password;
        this.schemeID = PasswordRecipient.PKCS5_SCHEME2_UTF8;
        this.kekAlgorithm = kekAlgorithm;
        this.keySize = keySize;
        this.blockSize = blockSize;
        this.prf = PasswordRecipient.PRF.HMacSHA1;
        this.iterationCount = 1024;
    }

    private static int getKeySize(ASN1ObjectIdentifier kekAlgorithm)
    {
        Integer size = (Integer)PasswordRecipientInformation.KEYSIZES.get(kekAlgorithm);

        if (size == null)
        {
            // RFC 3211 sec. 2.3 (PWRI-KEK) requires the inner key encryption
            // algorithm to be a CBC-mode block cipher. AEAD modes (e.g.
            // AES_GCM) and key-wrap mechanisms (e.g. AES_WRAP / AES_WRAP_PAD)
            // are not valid here — the AEAD or wrap construction is for the
            // content encryption, not for the password-derived KEK. Use
            // AES{128,192,256}_CBC, DES_EDE3_CBC, or CAMELLIA{128,192,256}_CBC
            // as the kekAlgorithm and pass the AEAD / wrap algorithm to the
            // CMSEnvelopedDataGenerator content encryptor instead.
            throw new IllegalArgumentException(
                "kekAlgorithm " + kekAlgorithm + " is not a supported PWRI-KEK CBC-mode block cipher; "
                    + "see RFC 3211 sec. 2.3 (use AES_CBC, DES_EDE3_CBC or CAMELLIA_CBC variants)");
        }

        return size.intValue();
    }

    public PasswordRecipientInfoGenerator setPasswordConversionScheme(int schemeID)
    {
        this.schemeID = schemeID;

        return this;
    }

    public PasswordRecipientInfoGenerator setPRF(PasswordRecipient.PRF prf)
    {
        this.prf = prf;

        return this;
    }

    public PasswordRecipientInfoGenerator setSaltAndIterationCount(byte[] salt, int iterationCount)
    {
        this.salt = Arrays.clone(salt);
        this.iterationCount = iterationCount;

        return this;
    }

    public PasswordRecipientInfoGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException
    {
        byte[] iv = new byte[blockSize];     /// TODO: set IV size properly!

        if (random == null)
        {
            random = new SecureRandom();
        }
        
        random.nextBytes(iv);

        if (salt == null)
        {
            salt = new byte[20];

            random.nextBytes(salt);
        }

        keyDerivationAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, iterationCount, prf.prfAlgID));

        byte[] derivedKey = calculateDerivedKey(schemeID, keyDerivationAlgorithm, keySize);

        AlgorithmIdentifier kekAlgorithmId = new AlgorithmIdentifier(kekAlgorithm, new DEROctetString(iv));

        byte[] encryptedKeyBytes = generateEncryptedBytes(kekAlgorithmId, derivedKey, contentEncryptionKey);

        ASN1OctetString encryptedKey = new DEROctetString(encryptedKeyBytes);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(kekAlgorithm);
        v.add(new DEROctetString(iv));

        AlgorithmIdentifier keyEncryptionAlgorithm = new AlgorithmIdentifier(
            PKCSObjectIdentifiers.id_alg_PWRI_KEK, new DERSequence(v));

        return new RecipientInfo(new PasswordRecipientInfo(keyDerivationAlgorithm,
            keyEncryptionAlgorithm, encryptedKey));
    }

    protected abstract byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
        throws CMSException;

    protected abstract byte[] generateEncryptedBytes(AlgorithmIdentifier algorithm, byte[] derivedKey, GenericKey contentEncryptionKey)
        throws CMSException;
}