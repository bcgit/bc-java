package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * Return a factory for {@link PBESecretKeyEncryptor} instances which protect the secret key material by deriving
 * a key-encryption-key using {@link org.bouncycastle.bcpg.S2K#SALTED_AND_ITERATED} S2K and apply
 * that key using {@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_SHA1} (CFB mode).
 * <p>
 * This particular factory derives a key-encryption-key via salted+iterated S2K derivation using SHA256
 * and uses AES256 for secret key protection.
 */
public class BcCFBSecretKeyEncryptorFactory
        extends PBESecretKeyEncryptorFactory
{
    @Override
    public PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKeyPacket)
    {
        PGPDigestCalculator checksumCalc;
        try
        {
            checksumCalc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);
        }
        catch (PGPException e)
        {
            throw new RuntimeException(e); // Does not happen in practice
        }

        return new BcPBESecretKeyEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256,
                checksumCalc,
                0xff) // MAX iteration count
                .build(passphrase);
    }
}
