package org.bouncycastle.cms.bc;

import java.io.InputStream;

import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.InputDecryptor;

class CMSUtils
{
    static CipherParameters getBcKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof CipherParameters)
        {
            return (CipherParameters)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new KeyParameter((byte[])key.getRepresentation());
        }

        throw new IllegalArgumentException("unknown generic key type");
    }

    static RecipientOperator getRecipientOperator(final AlgorithmIdentifier contentEncryptionAlgorithm, CipherParameters secretKey)
        throws CMSException
    {
        final Object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputDecryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataOut)
            {
                if (dataCipher instanceof BufferedBlockCipher)
                {
                    return new CipherInputStream(dataOut, (BufferedBlockCipher)dataCipher);
                }
                else
                {
                    return new CipherInputStream(dataOut, (StreamCipher)dataCipher);
                }
            }
        });
    }

    static byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize, char[] password)
        throws CMSException
    {
        PBKDF2Params params = PBKDF2Params.getInstance(derivationAlgorithm.getParameters());
        byte[] encodedPassword = (schemeID == PasswordRecipient.PKCS5_SCHEME2) ? PBEParametersGenerator.PKCS5PasswordToBytes(password) : PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);

        try
        {
            PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(EnvelopedDataHelper.getPRF(params.getPrf()));

            gen.init(encodedPassword, params.getSalt(), params.getIterationCount().intValue());

            return ((KeyParameter)gen.generateDerivedParameters(keySize)).getKey();
        }
        catch (Exception e)
        {
            throw new CMSException("exception creating derived key: " + e.getMessage(), e);
        }
    }
}
