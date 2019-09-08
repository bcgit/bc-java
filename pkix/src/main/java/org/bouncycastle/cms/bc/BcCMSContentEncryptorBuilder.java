package org.bouncycastle.cms.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.CipherFactory;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Integers;

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
    private final int keySize;

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
        if (helper.isAuthEnveloped(encryptionOID))
        {
            return new CMSAuthOutputEncryptor(encryptionOID, keySize, random);
        }
        return new CMSOutputEncryptor(encryptionOID, keySize, random);
    }

    private class CMSOutputEncryptor
        implements OutputEncryptor
    {
        private KeyParameter encKey;
        private AlgorithmIdentifier algorithmIdentifier;
        protected Object cipher;

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

    private class CMSAuthOutputEncryptor
        extends CMSOutputEncryptor
        implements OutputAEADEncryptor
    {
        private AEADBlockCipher aeadCipher;

        CMSAuthOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
            throws CMSException
        {
            super(encryptionOID, keySize, random);

            aeadCipher = getCipher();
        }

        private AEADBlockCipher getCipher()
        {
            if (!(cipher instanceof AEADBlockCipher))
            {
                throw new IllegalArgumentException("Unable to create Authenticated Output Encryptor without Authenticaed Data cipher!");
            }
            return (AEADBlockCipher)cipher;
        }

        public OutputStream getAADStream()
        {
            return new AADStream(aeadCipher);
        }

        public byte[] getMAC()
        {
            return aeadCipher.getMac();
        }
    }

    private static class AADStream
        extends OutputStream
    {
        private AEADBlockCipher cipher;

        public AADStream(AEADBlockCipher cipher)
        {
            this.cipher = cipher;
        }

        public void write(byte[] buf, int off, int len)
            throws IOException
        {
            cipher.processAADBytes(buf, off, len);
        }
        
        public void write(int b)
            throws IOException
        {
            cipher.processAADByte((byte)b);
        }
    }
}
