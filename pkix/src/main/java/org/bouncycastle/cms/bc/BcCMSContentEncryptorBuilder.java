package org.bouncycastle.cms.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.CipherFactory;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCaptureStream;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.SecretKeySizeProvider;

public class BcCMSContentEncryptorBuilder
{
    private static final SecretKeySizeProvider KEY_SIZE_PROVIDER = DefaultSecretKeySizeProvider.INSTANCE;

    private final ASN1ObjectIdentifier encryptionOID;
    private final int keySize;

    private EnvelopedDataHelper helper = new EnvelopedDataHelper();
    private SecureRandom random;

    public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID)
    {
        this(encryptionOID, KEY_SIZE_PROVIDER.getKeySize(encryptionOID));
    }

    public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
    {
        this.encryptionOID = encryptionOID;
        int fixedSize = KEY_SIZE_PROVIDER.getKeySize(encryptionOID);

        if (encryptionOID.equals(PKCSObjectIdentifiers.des_EDE3_CBC))
        {
            if (keySize != 168 && keySize != fixedSize)
            {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = 168;
        }
        else if (encryptionOID.equals(OIWObjectIdentifiers.desCBC))
        {
            if (keySize != 56 && keySize != fixedSize)
            {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = 56;
        }
        else
        {
            if (fixedSize > 0 && fixedSize != keySize)
            {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = keySize;
        }
    }

    public BcCMSContentEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    /**
     * Build the OutputEncryptor with an internally generated key.
     *
     * @return an OutputEncryptor configured to use an internal key.
     * @throws CMSException
     */
    public OutputEncryptor build()
        throws CMSException
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        CipherKeyGenerator keyGen = helper.createKeyGenerator(encryptionOID, keySize, random);

        return build(keyGen.generateKey());
    }

    /**
     * Build the OutputEncryptor using a pre-generated key.
     *
     * @param rawEncKey a raw byte encoding of the key to be used for encryption.
     * @return an OutputEncryptor configured to use rawEncKey.
     * @throws CMSException
     */
    public OutputEncryptor build(byte[] rawEncKey)
        throws CMSException
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        // fixed key size defined
        if (this.keySize > 0)
        {
            if (((this.keySize + 7) / 8) != rawEncKey.length)
            {
                if ((this.keySize != 56 && rawEncKey.length != 8)
                    && (this.keySize != 168 && rawEncKey.length != 24))
                {
                    throw new IllegalArgumentException("attempt to create encryptor with the wrong sized key");
                }
            }
        }
   
        if (helper.isAuthEnveloped(encryptionOID))
        {
            return new CMSAuthOutputEncryptor(encryptionOID, new KeyParameter(rawEncKey), random);
        }

        return new CMSOutputEncryptor(encryptionOID, new KeyParameter(rawEncKey), random);
    }

    private class CMSOutputEncryptor
        implements OutputEncryptor
    {
        private KeyParameter encKey;
        private AlgorithmIdentifier algorithmIdentifier;
        protected Object cipher;

        CMSOutputEncryptor(ASN1ObjectIdentifier encryptionOID, KeyParameter encKey, SecureRandom random)
            throws CMSException
        {
            this.algorithmIdentifier = helper.generateEncryptionAlgID(encryptionOID, encKey, random);
            this.encKey = encKey;
            this.cipher = EnvelopedDataHelper.createContentCipher(true, encKey, algorithmIdentifier);
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
        private MacCaptureStream macOut;

        CMSAuthOutputEncryptor(ASN1ObjectIdentifier encryptionOID, KeyParameter encKey, SecureRandom random)
            throws CMSException
        {
            super(encryptionOID, encKey, random);

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

        public OutputStream getOutputStream(OutputStream dOut)
        {
            macOut = new MacCaptureStream(dOut, aeadCipher.getMac().length);
            return CipherFactory.createOutputStream(macOut, cipher);
        }

        public OutputStream getAADStream()
        {
            return new AADStream(aeadCipher);
        }

        public byte[] getMAC()
        {
            return macOut.getMac();
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
