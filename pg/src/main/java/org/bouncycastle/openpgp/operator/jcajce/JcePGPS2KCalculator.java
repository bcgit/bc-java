package org.bouncycastle.openpgp.operator.jcajce;

import java.security.GeneralSecurityException;
import java.security.Provider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.jcajce.spec.Argon2KeySpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPS2KCalculator;

/**
 * A {@link PGPS2KCalculator} for the JCA/JCE OpenPGP operators. The Argon2 key (RFC 9580 sec. 3.7.1.4)
 * is derived through the provider's {@code SecretKeyFactory.ARGON2} (RFC 9106) rather than the
 * lightweight engine directly, so the provider is overridable via {@link #setProvider}. The cost
 * parameters are bounded by the caller ({@code PGPUtil.makeKeyFromPassPhrase}) before this is invoked.
 */
public class JcePGPS2KCalculator
    implements PGPS2KCalculator
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    public JcePGPS2KCalculator()
    {
    }

    JcePGPS2KCalculator(OperatorHelper helper)
    {
        this.helper = helper;
    }

    public JcePGPS2KCalculator setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcePGPS2KCalculator setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public int getType()
    {
        return S2K.ARGON_2;
    }

    public byte[] makeKey(char[] passPhrase, S2K s2k, int keyLen)
        throws PGPException
    {
        if (s2k.getType() != S2K.ARGON_2)
        {
            throw new PGPException("s2k function not Argon2");
        }

        try
        {
            SecretKeyFactory factory = helper.createSecretKeyFactory("ARGON2");

            Argon2KeySpec keySpec = new Argon2KeySpec(
                Argon2KeySpec.ARGON2_id, Argon2KeySpec.ARGON2_VERSION_13,
                passPhrase, s2k.getIV(),
                s2k.getPasses(), 1 << s2k.getMemorySizeExponent(), s2k.getParallelism(),
                keyLen * 8);

            SecretKey key = factory.generateSecret(keySpec);

            return key.getEncoded();
        }
        catch (GeneralSecurityException e)
        {
            throw new PGPException("unable to derive Argon2 key: " + e.getMessage(), e);
        }
    }
}
