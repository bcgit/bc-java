package org.bouncycastle.tls.crypto.impl.jcajce.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.TlsHash;

/**
 * Implements the client side SRP-6a protocol. Note that this class is stateful, and therefore NOT threadsafe.
 * This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
 * "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
 */
public class SRP6Client
{
    protected BigInteger N;
    protected BigInteger g;

    protected BigInteger a;
    protected BigInteger A;

    protected BigInteger B;

    protected BigInteger x;
    protected BigInteger u;
    protected BigInteger S;

    protected BigInteger M1;
	protected BigInteger M2;
	protected BigInteger Key;
	
    protected TlsHash digest;
    protected SecureRandom random;

    public SRP6Client()
    {
    }

    /**
     * Initialises the client to begin new authentication attempt
     * @param N The safe prime associated with the client's verifier
     * @param g The group parameter associated with the client's verifier
     * @param digest The digest algorithm associated with the client's verifier
     * @param random For key generation
     */
    public void init(BigInteger N, BigInteger g, TlsHash digest, SecureRandom random)
    {
        this.N = N;
        this.g = g;
        this.digest = digest;
        this.random = random;
    }

    public void init(SRP6Group group, TlsHash digest, SecureRandom random)
    {
        init(group.getN(), group.getG(), digest, random);
    }

    /**
     * Generates client's credentials given the client's salt, identity and password
     * @param salt The salt used in the client's verifier.
     * @param identity The user's identity (eg. username)
     * @param password The user's password
     * @return Client's public value to send to server
     */
    public BigInteger generateClientCredentials(byte[] salt, byte[] identity, byte[] password)
    {
        this.x = SRP6Util.calculateX(digest, N, salt, identity, password);
        this.a = selectPrivateValue();
        this.A = g.modPow(a, N);

        return A;
    }

    /**
     * Generates the secret S given the server's credentials
     * @param serverB The server's credentials
     * @return Client's verification message for the server
     * @throws IllegalArgumentException If server's credentials are invalid
     */
    public BigInteger calculateSecret(BigInteger serverB)
    {
        this.B = SRP6Util.validatePublicValue(N, serverB);
        this.u = SRP6Util.calculateU(digest, N, A, B);
        this.S = calculateS();

        return S;
    }

    protected BigInteger selectPrivateValue()
    {
        return SRP6Util.generatePrivateValue(N, g, random);
    }

    private BigInteger calculateS()
    {
        BigInteger k = SRP6Util.calculateK(digest, N, g);
        BigInteger exp = u.multiply(x).add(a);
        BigInteger tmp = g.modPow(x, N).multiply(k).mod(N);
        return B.subtract(tmp).mod(N).modPow(exp, N);
    }

    /**
	 * Computes the client evidence message M1 using the previously received values.
	 * To be called after calculating the secret S.
	 * @return M1: the client side generated evidence message
	 * @throws IllegalStateException
	 */
	public BigInteger calculateClientEvidenceMessage() throws IllegalStateException
	{
		// Verify pre-requirements
		if (this.A == null || this.B == null || this.S == null)
		{
			throw new IllegalStateException("Impossible to compute M1: " +
					"some data are missing from the previous operations (A,B,S)");
		}
		// compute the client evidence message 'M1'
		this.M1 = SRP6Util.calculateM1(digest, N, A, B, S);
		return M1;
	}

	/** Authenticates the server evidence message M2 received and saves it only if correct.
	 * @param serverM2 the server side generated evidence message
	 * @return A boolean indicating if the server message M2 was the expected one.
	 * @throws IllegalStateException
	 */
	public boolean verifyServerEvidenceMessage(BigInteger serverM2) throws IllegalStateException
	{
		// Verify pre-requirements
		if (this.A == null || this.M1 == null || this.S == null)
		{
			throw new IllegalStateException("Impossible to compute and verify M2: " +
					"some data are missing from the previous operations (A,M1,S)");
		}

		// Compute the own server evidence message 'M2'
		BigInteger computedM2 = SRP6Util.calculateM2(digest, N, A, M1, S);
		if (computedM2.equals(serverM2))
		{
			this.M2 = serverM2;
			return true;
		}
		return false;
	}

	/**
	 * Computes the final session key as a result of the SRP successful mutual authentication
	 * To be called after verifying the server evidence message M2.
	 * @return Key: the mutually authenticated symmetric session key
	 * @throws IllegalStateException
	 */
	public BigInteger calculateSessionKey() throws IllegalStateException
	{
		// Verify pre-requirements (here we enforce a previous calculation of M1 and M2)
		if (this.S == null || this.M1 == null || this.M2 == null)
		{
			throw new IllegalStateException("Impossible to compute Key: " +
					"some data are missing from the previous operations (S,M1,M2)");
		}
		this.Key = SRP6Util.calculateKey(digest, N, S);
		return Key;
	}
}
