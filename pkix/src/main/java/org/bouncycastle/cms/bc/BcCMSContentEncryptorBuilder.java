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

/**
 * Lightweight builder for the content encryptor used in CMS {@code EnvelopedData},
 * {@code AuthEnvelopedData} and {@code EncryptedData} structures &mdash; i.e. it
 * encrypts the actual transmitted (or stored) content.
 * <p>
 * The no-arg {@link #build()} call generates a fresh content-encryption key
 * internally, which is the right behaviour for {@code EnvelopedData} where the
 * CEK is freshly drawn per message and wrapped per recipient. Callers that
 * already have a key &mdash; e.g. building an {@code EncryptedData} blob over
 * a long-lived locally-stored key (no recipients, no intermediate key wrap)
 * &mdash; should use {@link #build(byte[])} or {@link #build(KeyParameter)}
 * instead.
 * </p>
 */
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
        return build(new KeyParameter(rawEncKey));
    }

    /**
     * Build the OutputEncryptor using a pre-generated key in lightweight
     * {@link KeyParameter} form. The lightweight peer of
     * {@code JceCMSContentEncryptorBuilder.build(SecretKey)}; useful when the
     * caller already holds a {@code KeyParameter} (e.g. derived via
     * {@code HKDFBytesGenerator} or returned by another BC lightweight key
     * agreement) and would otherwise round-trip the key through
     * {@code byte[]} for no reason.
     *
     * @param encKey the pre-generated key to use for content encryption.
     * @return an OutputEncryptor configured to use encKey.
     * @throws CMSException
     */
    public OutputEncryptor build(KeyParameter encKey)
        throws CMSException
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        // fixed key size defined
        byte[] keyBytes = encKey.getKey();
        if (this.keySize > 0)
        {
            if (((this.keySize + 7) / 8) != keyBytes.length)
            {
                if ((this.keySize != 56 && keyBytes.length != 8)
                    && (this.keySize != 168 && keyBytes.length != 24))
                {
                    throw new IllegalArgumentException("attempt to create encryptor with the wrong sized key");
                }
            }
        }

        if (helper.isAuthEnveloped(encryptionOID))
        {
            return new CMSAuthOutputEncryptor(encryptionOID, encKey, random);
        }

        return new CMSOutputEncryptor(encryptionOID, encKey, random);
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
