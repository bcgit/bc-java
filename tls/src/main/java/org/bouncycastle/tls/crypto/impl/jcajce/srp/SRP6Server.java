package org.bouncycastle.tls.crypto.impl.jcajce.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.TlsHash;

/**
 * Implements the server side SRP-6a protocol. Note that this class is stateful, and therefore NOT threadsafe.
 * This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
 * "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
 */
public class SRP6Server
{
    protected BigInteger N;
    protected BigInteger g;
    protected BigInteger v;

    protected SecureRandom random;
    protected TlsHash digest;

    protected BigInteger A;

    protected BigInteger b;
    protected BigInteger B;

    protected BigInteger u;
    protected BigInteger S;
    protected BigInteger M1;
	protected BigInteger M2;
	protected BigInteger Key;
	
    public SRP6Server()
    {
    }

    /**
     * Initialises the server to accept a new client authentication attempt
     * @param N The safe prime associated with the client's verifier
     * @param g The group parameter associated with the client's verifier
     * @param v The client's verifier
     * @param digest The digest algorithm associated with the client's verifier
     * @param random For key generation
     */
    public void init(BigInteger N, BigInteger g, BigInteger v, TlsHash digest, SecureRandom random)
    {
        this.N = N;
        this.g = g;
        this.v = v;

        this.random = random;
        this.digest = digest;
    }

    public void init(SRP6Group group, BigInteger v, TlsHash digest, SecureRandom random)
    {
        init(group.getN(), group.getG(), v, digest, random);
    }

    /**
     * Generates the server's credentials that are to be sent to the client.
     * @return The server's public value to the client
     */
    public BigInteger generateServerCredentials()
    {
        BigInteger k = SRP6Util.calculateK(digest, N, g);
        this.b = selectPrivateValue();
        this.B = k.multiply(v).mod(N).add(g.modPow(b, N)).mod(N);

        return B;
    }

    /**
     * Processes the client's credentials. If valid the shared secret is generated and returned.
     * @param clientA The client's credentials
     * @return A shared secret BigInteger
     * @throws IllegalArgumentException If client's credentials are invalid
     */
    public BigInteger calculateSecret(BigInteger clientA) throws IllegalArgumentException
    {
        this.A = SRP6Util.validatePublicValue(N, clientA);
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
        return v.modPow(u, N).multiply(A).mod(N).modPow(b, N);
    }

    /**
	 * Authenticates the received client evidence message M1 and saves it only if correct.
	 * To be called after calculating the secret S.
	 * @param clientM1 the client side generated evidence message
	 * @return A boolean indicating if the client message M1 was the expected one.
	 * @throws IllegalStateException
	 */
	public boolean verifyClientEvidenceMessage(BigInteger clientM1) throws IllegalStateException
	{
		// Verify pre-requirements
		if (this.A == null || this.B == null || this.S == null)
		{
			throw new IllegalStateException("Impossible to compute and verify M1: " +
					"some data are missing from the previous operations (A,B,S)");
		}

		// Compute the own client evidence message 'M1'
		BigInteger computedM1 = SRP6Util.calculateM1(digest, N, A, B, S);
		if (computedM1.equals(clientM1))
		{
			this.M1 = clientM1;
			return true;
		}
		return false;
	}

	/**
	 * Computes the server evidence message M2 using the previously verified values.
	 * To be called after successfully verifying the client evidence message M1.
	 * @return M2: the server side generated evidence message
	 * @throws IllegalStateException
	 */
	public BigInteger calculateServerEvidenceMessage() throws IllegalStateException
	{
		// Verify pre-requirements
		if (this.A == null || this.M1 == null || this.S == null)
		{
			throw new IllegalStateException("Impossible to compute M2: " +
					"some data are missing from the previous operations (A,M1,S)");
		}

		// Compute the server evidence message 'M2'
		this.M2 = SRP6Util.calculateM2(digest, N, A, M1, S);
		return M2;
	}

	/**
	 * Computes the final session key as a result of the SRP successful mutual authentication
	 * To be called after calculating the server evidence message M2.
	 * @return Key: the mutual authenticated symmetric session key
	 * @throws IllegalStateException
	 */
	public BigInteger calculateSessionKey() throws IllegalArgumentException
	{
		// Verify pre-requirements
		if (this.S == null || this.M1 == null || this.M2 == null)
		{
			throw new IllegalStateException("Impossible to compute Key: " +
					"some data are missing from the previous operations (S,M1,M2)");
		}
		this.Key = SRP6Util.calculateKey(digest, N, S);
		return Key;
	}
}
