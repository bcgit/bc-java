package org.bouncycastle.tls.crypto.impl.jcajce.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.BigIntegers;

/**
 * Generates new SRP verifier for user
 */
public class SRP6VerifierGenerator
{
    protected BigInteger N;
    protected BigInteger g;
    protected TlsHash digest;
    protected SecureRandom random;

    public SRP6VerifierGenerator()
    {
    }

    /**
     * Initialises generator to create new verifiers
     * @param N The safe prime to use (see DHParametersGenerator)
     * @param g The group parameter to use (see DHParametersGenerator)
     * @param digest The digest to use. The same digest type will need to be used later for the actual authentication
     * attempt. Also note that the final session key size is dependent on the chosen digest.
     */
    public void init(BigInteger N, BigInteger g, TlsHash digest)
    {
        init(N, g, digest, null);
    }

    /**
     * Initialises generator to create new verifiers
     * @param N The safe prime to use (see DHParametersGenerator)
     * @param g The group parameter to use (see DHParametersGenerator)
     * @param digest The digest to use. The same digest type will need to be used later for the actual authentication
     * attempt. Also note that the final session key size is dependent on the chosen digest.
     * @param random The source used to randomise the private exponent before it is raised, may be null
     * to take the default from CryptoServicesRegistrar.
     */
    public void init(BigInteger N, BigInteger g, TlsHash digest, SecureRandom random)
    {
        this.N = N;
        this.g = g;
        this.digest = digest;
        this.random = random;
    }

    public void init(SRP6Group group, TlsHash digest)
    {
        init(group, digest, null);
    }

    public void init(SRP6Group group, TlsHash digest, SecureRandom random)
    {
        init(group.getN(), group.getG(), digest, random);
    }

    /**
     * Creates a new SRP verifier
     * @param salt The salt to use, generally should be large and random
     * @param identity The user's identifying information (eg. username)
     * @param password The user's password
     * @return A new verifier for use in future SRP authentication
     */
    public BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password)
    {
        BigInteger x = SRP6Util.calculateX(digest, N, salt, identity, password);

        // x is derived from the password, making it the longest lived secret in the protocol, so the
        // exponent is randomised before the variable-time BigInteger.modPow sees it. Raising g to
        // the power N-1 gives 1 by Fermat's little theorem, so the verifier is unchanged.
        BigInteger blindedX = BigIntegers.createBlindedExponent(x, N.subtract(BigIntegers.ONE),
            CryptoServicesRegistrar.getSecureRandom(random));

        return g.modPow(blindedX, N);
    }
}
