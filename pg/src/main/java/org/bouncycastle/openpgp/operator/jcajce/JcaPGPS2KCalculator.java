package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPS2KCalculator;

/**
 * A {@link PGPS2KCalculator} for the JCA/JCE OpenPGP operators. Neither the JDK nor the Bouncy Castle
 * JCE provider exposes Argon2, so this delegates to the lightweight {@link Argon2BytesGenerator} - the
 * only Argon2 implementation Bouncy Castle ships. The cost parameters are bounded by the caller
 * ({@code PGPUtil.makeKeyFromPassPhrase}) before this is invoked.
 */
public class JcaPGPS2KCalculator
    implements PGPS2KCalculator
{
    public byte[] makeKey(char[] passPhrase, S2K s2k, int keyLen)
        throws PGPException
    {
        if (s2k.getType() != S2K.ARGON_2)
        {
            throw new PGPException("s2k function not Argon2");
        }

        byte[] keyBytes = new byte[keyLen];

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(s2k.getIV())
            .withIterations(s2k.getPasses())
            .withParallelism(s2k.getParallelism())
            .withMemoryPowOfTwo(s2k.getMemorySizeExponent())
            .withVersion(Argon2Parameters.ARGON2_VERSION_13);

        Argon2BytesGenerator argon2 = new Argon2BytesGenerator();
        argon2.init(builder.build());
        argon2.generateBytes(passPhrase, keyBytes);

        return keyBytes;
    }
}
