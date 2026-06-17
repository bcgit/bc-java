package org.bouncycastle.pkcs.jcajce;

import java.security.PrivateKey;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;

/**
 * JCA-aware extension of {@link PKCS8EncryptedPrivateKeyInfoBuilder} that accepts a standard
 * {@link PrivateKey} as input.
 */
public class JcaPKCS8EncryptedPrivateKeyInfoBuilder
    extends PKCS8EncryptedPrivateKeyInfoBuilder
{
    /**
     * Base constructor.
     *
     * @param privateKey the JCA private key to be encrypted.
     */
    public JcaPKCS8EncryptedPrivateKeyInfoBuilder(PrivateKey privateKey)
    {
         super(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
    }
}
