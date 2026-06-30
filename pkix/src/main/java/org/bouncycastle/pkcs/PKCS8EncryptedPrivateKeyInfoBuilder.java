package org.bouncycastle.pkcs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Exceptions;
/**
 * A class for creating EncryptedPrivateKeyInfo structures.
 * <pre>
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *      encryptionAlgorithm AlgorithmIdentifier {{KeyEncryptionAlgorithms}},
 *      encryptedData EncryptedData
 * }
 *
 * EncryptedData ::= OCTET STRING
 *
 * KeyEncryptionAlgorithms ALGORITHM-IDENTIFIER ::= {
 *          ... -- For local profiles
 * }
 * </pre>
 */
public class PKCS8EncryptedPrivateKeyInfoBuilder
{
    private PrivateKeyInfo privateKeyInfo;

    /**
     * Construct a builder around a DER-encoded {@link PrivateKeyInfo}.
     *
     * @param privateKeyInfo the encoded private-key bytes.
     */
    public PKCS8EncryptedPrivateKeyInfoBuilder(byte[] privateKeyInfo)
    {
        this(PrivateKeyInfo.getInstance(privateKeyInfo));
    }

    /**
     * Construct a builder around a parsed {@link PrivateKeyInfo}.
     *
     * @param privateKeyInfo the private key to be encrypted.
     */
    public PKCS8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo privateKeyInfo)
    {
        this.privateKeyInfo = privateKeyInfo;
    }

    /**
     * Encrypt the wrapped private key with {@code encryptor}.
     *
     * @param encryptor a configured output encryptor.
     * @return the resulting {@link PKCS8EncryptedPrivateKeyInfo}.
     */
    public PKCS8EncryptedPrivateKeyInfo build(
        OutputEncryptor encryptor)
    {
        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            OutputStream cOut = encryptor.getOutputStream(bOut);

            cOut.write(privateKeyInfo.getEncoded());

            cOut.close();

            return new PKCS8EncryptedPrivateKeyInfo(new EncryptedPrivateKeyInfo(encryptor.getAlgorithmIdentifier(), bOut.toByteArray()));
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("cannot encode privateKeyInfo", e);
        }
    }
}
