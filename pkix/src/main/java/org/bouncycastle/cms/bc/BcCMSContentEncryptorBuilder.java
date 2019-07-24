package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.CipherFactory;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Integers;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class BcCMSContentEncryptorBuilder
{
    private static Map keySizes = new HashMap();

    static
    {
        keySizes.put(CMSAlgorithm.AES128_CBC, Integers.valueOf(128));
        keySizes.put(CMSAlgorithm.AES192_CBC, Integers.valueOf(192));
        keySizes.put(CMSAlgorithm.AES256_CBC, Integers.valueOf(256));

        keySizes.put(CMSAlgorithm.AES128_GCM, Integers.valueOf(128));
        keySizes.put(CMSAlgorithm.AES192_GCM, Integers.valueOf(192));
        keySizes.put(CMSAlgorithm.AES256_GCM, Integers.valueOf(256));

        keySizes.put(CMSAlgorithm.CAMELLIA128_CBC, Integers.valueOf(128));
        keySizes.put(CMSAlgorithm.CAMELLIA192_CBC, Integers.valueOf(192));
        keySizes.put(CMSAlgorithm.CAMELLIA256_CBC, Integers.valueOf(256));
    }

    private static int getKeySize(ASN1ObjectIdentifier oid)
    {
        Integer size = (Integer)keySizes.get(oid);

        if (size != null)
        {
            return size.intValue();
        }

        return -1;
    }

    private final ASN1ObjectIdentifier encryptionOID;
    private final int                  keySize;

    private EnvelopedDataHelper helper = new EnvelopedDataHelper();
    private SecureRandom random;

    public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID)
    {
        this(encryptionOID, getKeySize(encryptionOID));
    }

    public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
    {
        this.encryptionOID = encryptionOID;
        this.keySize = keySize;
    }

    public BcCMSContentEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public OutputEncryptor build()
        throws CMSException
    {
        if(helper.isAuthEnveloped(encryptionOID)){
            return new CMSAuthOutputEncryptor(encryptionOID, keySize, random);
        }
        return new CMSOutputEncryptor(encryptionOID, keySize, random);
    }

    private class CMSOutputEncryptor
        implements OutputEncryptor
    {
        private KeyParameter encKey;
        private AlgorithmIdentifier algorithmIdentifier;
        protected Object             cipher;

        CMSOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
            throws CMSException
        {
            if (random == null)
            {
                random = new SecureRandom();
            }

            CipherKeyGenerator keyGen = helper.createKeyGenerator(encryptionOID, random);

            encKey = new KeyParameter(keyGen.generateKey());

            algorithmIdentifier = helper.generateEncryptionAlgID(encryptionOID, encKey, random);

            cipher = EnvelopedDataHelper.createContentCipher(true, encKey, algorithmIdentifier);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut)
        {
            return CipherFactory.createOutputStream(dOut, cipher);
        }

        public GenericKey getKey()
        {
            return new GenericKey(algorithmIdentifier, encKey.getKey());
        }
    }

    public interface MacProvider{
        byte[] addAuthenticatedAttributes(AttributeTable authAttributes) throws IOException;
        byte[] getMac();
    }
    private class CMSAuthOutputEncryptor extends CMSOutputEncryptor implements MacProvider {
        CMSAttributeTableGenerator authenticatedAttributeGenerator;

        CMSAuthOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
                throws CMSException
        {
            super(encryptionOID, keySize, random);
            //check the cipher is able to produce authenticated results.
            getCipher();
        }

        private AEADBlockCipher getCipher()
        {
            if(!(cipher instanceof AEADBlockCipher)){
                throw new IllegalArgumentException("Unable to create Authenticated Output Encryptor without Authenticaed Data cipher!") ;
            }
            return (AEADBlockCipher)cipher;
        }

        byte[] aad = null;
        public byte[] addAuthenticatedAttributes(AttributeTable authAttributes) throws IOException {
            aad = new DERSet(authAttributes.toASN1EncodableVector())
                        .toASN1Primitive().getEncoded();
            return aad;
        }

        public byte[] getMac() {
            if(aad != null){
                getCipher().processAADBytes(aad, 0, aad.length);
            }
            return getCipher().getMac();
        }
    }
}
