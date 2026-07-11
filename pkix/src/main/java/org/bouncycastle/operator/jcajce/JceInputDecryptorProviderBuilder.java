package org.bouncycastle.operator.jcajce;

import java.io.InputStream;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OidCatalogue;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;

/**
 * A generic decryptor provider for IETF style algorithms.
 */
public class JceInputDecryptorProviderBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JceInputDecryptorProviderBuilder()
    {
    }

    public JceInputDecryptorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JceInputDecryptorProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    /**
     * Build a decryptor provider which will use the passed in bytes for the symmetric key.
     *
     * @param keyBytes bytes representing the key to use.
     * @return an decryptor provider.
     */
    public InputDecryptorProvider build(byte[] keyBytes)
    {
        final byte[] encKeyBytes = Arrays.clone(keyBytes);

        return new InputDecryptorProvider()
        {
            private Cipher cipher;
            private AlgorithmIdentifier encryptionAlg;

            public InputDecryptor get(final AlgorithmIdentifier algorithmIdentifier)
                throws OperatorCreationException
            {
                encryptionAlg = algorithmIdentifier;

                ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

                try
                {
                    cipher = helper.createCipher(algorithm.getId());
                    SecretKey key = new SecretKeySpec(encKeyBytes, algorithm.getId());
                    
                    ASN1Encodable encParams = algorithmIdentifier.getParameters();

                    if (OidCatalogue.isGCM(algorithm))
                    {
                        // RFC 5084 / RFC 3565 GCMParameters: nonce + icvLen (bytes).
                        GCMParameters gcm = GCMParameters.getInstance(encParams);
                        cipher.init(Cipher.DECRYPT_MODE, key,
                            new GCMParameterSpec(gcm.getIcvLen() * 8, gcm.getNonce()));
                    }
                    else if (OidCatalogue.isCCM(algorithm))
                    {
                        // RFC 5084 CCMParameters share the GCMParameters shape
                        // (nonce + icvLen); BC's CCM JCE init accepts a
                        // GCMParameterSpec with the tag length in bits.
                        CCMParameters ccm = CCMParameters.getInstance(encParams);
                        cipher.init(Cipher.DECRYPT_MODE, key,
                            new GCMParameterSpec(ccm.getIcvLen() * 8, ccm.getNonce()));
                    }
                    else if (encParams instanceof ASN1OctetString)
                    {
                        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
                    }
                    else
                    {
                        // Last resort: GOST 28147 parameters.
                        GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

                        cipher.init(Cipher.DECRYPT_MODE, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
                    }
                }
                catch (Exception e)
                {
                    throw new OperatorCreationException("unable to create InputDecryptor: " + e.getMessage(), e);
                }

                return new InputDecryptor()
                {
                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return encryptionAlg;
                    }

                    public InputStream getInputStream(InputStream input)
                    {
                        return new CipherInputStream(input, cipher);
                    }
                };
            }
        };
    }
}
