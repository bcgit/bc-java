package org.bouncycastle.pkcs;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.util.io.Streams;

/**
 * Holding class for a PKCS#8 EncryptedPrivateKeyInfo structure (RFC 5958, originally RFC 5208).
 */
public class PKCS8EncryptedPrivateKeyInfo
{
    private EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

    private static EncryptedPrivateKeyInfo parseBytes(byte[] pkcs8Encoding)
        throws IOException
    {
        try
        {
            return EncryptedPrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(pkcs8Encoding));
        }
        catch (ClassCastException e)
        {
            throw new PKCSIOException("malformed data: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new PKCSIOException("malformed data: " + e.getMessage(), e);
        }
    }

    /**
     * Wrap an existing parsed {@link EncryptedPrivateKeyInfo} structure.
     *
     * @param encryptedPrivateKeyInfo the ASN.1 structure to wrap.
     */
    public PKCS8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
    {
        this.encryptedPrivateKeyInfo = encryptedPrivateKeyInfo;
    }

    /**
     * Parse a BER/DER encoded EncryptedPrivateKeyInfo.
     *
     * @param encryptedPrivateKeyInfo the encoded bytes.
     * @throws IOException if the data is not a valid EncryptedPrivateKeyInfo encoding.
     */
    public PKCS8EncryptedPrivateKeyInfo(byte[] encryptedPrivateKeyInfo)
        throws IOException
    {
        this(parseBytes(encryptedPrivateKeyInfo));
    }

    /**
     * Return the algorithm identifier describing how the private key has been encrypted.
     */
    public AlgorithmIdentifier getEncryptionAlgorithm()
    {
        return encryptedPrivateKeyInfo.getEncryptionAlgorithm();
    }

    /**
     * Return the raw ciphertext bytes of the encrypted private key.
     */
    public byte[] getEncryptedData()
    {
        return encryptedPrivateKeyInfo.getEncryptedData();
    }

    /**
     * Return the underlying ASN.1 structure for this holder.
     */
    public EncryptedPrivateKeyInfo toASN1Structure()
    {
         return encryptedPrivateKeyInfo;
    }

    /**
     * Return the default (DER) encoding of this EncryptedPrivateKeyInfo.
     *
     * @return the encoded bytes.
     * @throws IOException if encoding fails.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return encryptedPrivateKeyInfo.getEncoded();
    }

    /**
     * Decrypt the wrapped private key.
     *
     * @param inputDecryptorProvider provider able to produce a decryptor matching the
     *                               encryption algorithm carried by this object.
     * @return the recovered {@link PrivateKeyInfo}.
     * @throws PKCSException if a decryptor cannot be created or decryption / parsing fails.
     */
    public PrivateKeyInfo decryptPrivateKeyInfo(InputDecryptorProvider inputDecryptorProvider)
        throws PKCSException
    {
        try
        {
            InputDecryptor decrytor = inputDecryptorProvider.get(encryptedPrivateKeyInfo.getEncryptionAlgorithm());

            ByteArrayInputStream encIn = new ByteArrayInputStream(encryptedPrivateKeyInfo.getEncryptedData());

            return PrivateKeyInfo.getInstance(Streams.readAll(decrytor.getInputStream(encIn)));
        }
        catch (Exception e)
        {
            throw new PKCSException("unable to read encrypted data: " + e.getMessage(), e);
        }
    }
}
