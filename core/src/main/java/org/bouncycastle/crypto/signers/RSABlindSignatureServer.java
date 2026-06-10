package org.bouncycastle.crypto.signers;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.BigIntegers;

/**
 * Server side of the RSA Blind Signature Scheme with Appendix (RSABSSA) defined
 * in RFC 9474. Implements the {@code BlindSign} step (sec. 4.3): given a blinded
 * message produced by {@link RSABlindSignatureClient#blind}, compute
 * {@code s = m^d mod n} and return it, after a self-consistency check
 * ({@code s^e == m mod n}) that catches CRT faults before the value leaves
 * the server.
 * <p>
 * The private-key operation is driven through
 * {@link org.bouncycastle.crypto.engines.RSABlindedEngine} so the modular
 * exponentiation is itself blinded against timing side-channels — orthogonal to
 * the RFC 9474 client/server blinding, which only hides the message.
 * <p>
 * The variant choice (PSS vs PSSZERO, randomised vs deterministic) is opaque
 * to the server — only the client cares — so this class is variant-agnostic.
 */
public class RSABlindSignatureServer
{
    private final RSAKeyParameters privateKey;
    private final BigInteger publicExponent;
    private final int modulusLen;
    private final AsymmetricBlockCipher engine;

    /**
     * @param privateKey the server's RSA private key. CRT-form
     *                   ({@link RSAPrivateCrtKeyParameters}) is strongly
     *                   recommended; the public exponent must be available
     *                   for the RSAVP1 self-check (RFC 9474 sec. 4.3 step 3).
     */
    public RSABlindSignatureServer(RSAKeyParameters privateKey)
    {
        if (privateKey == null)
        {
            throw new NullPointerException("'privateKey' cannot be null");
        }
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("RSA parameters should be for a private key");
        }

        BigInteger e = null;
        if (privateKey instanceof RSAPrivateCrtKeyParameters)
        {
            e = ((RSAPrivateCrtKeyParameters)privateKey).getPublicExponent();
        }
        if (e == null)
        {
            throw new IllegalArgumentException("public exponent required for RFC 9474 BlindSign self-check");
        }

        this.privateKey = privateKey;
        this.publicExponent = e;
        this.modulusLen = BigIntegers.getUnsignedByteLength(privateKey.getModulus());
        this.engine = new RSABlindedEngine();
        this.engine.init(true, privateKey);
    }

    /**
     * RFC 9474 sec. 4.3 {@code BlindSign}. Verifies {@code blindedMsg} as an
     * integer in {@code [0, n)} of the modulus length, applies RSASP1, and
     * checks that RSAVP1 round-trips back to the input before returning.
     *
     * @param blindedMsg the blinded message received from the client; must be
     *                   exactly {@code modulus_len} bytes.
     * @return the blinded signature, {@code modulus_len} bytes.
     * @throws CryptoException if the input is the wrong length, out of range,
     *                         or the RSASP1/RSAVP1 round-trip fails (CRT fault).
     */
    public byte[] blindSign(byte[] blindedMsg)
        throws CryptoException
    {
        if (blindedMsg.length != modulusLen)
        {
            throw new CryptoException("blinded message has wrong length: expected "
                + modulusLen + ", got " + blindedMsg.length);
        }

        BigInteger n = privateKey.getModulus();
        BigInteger m = BigIntegers.fromUnsignedByteArray(blindedMsg);
        if (m.compareTo(n) >= 0)
        {
            throw new CryptoException("blinded message out of range");
        }

        byte[] sBytes;
        try
        {
            sBytes = engine.processBlock(blindedMsg, 0, blindedMsg.length);
        }
        catch (Exception ex)
        {
            throw new CryptoException("signing failure", ex);
        }

        BigInteger s = BigIntegers.fromUnsignedByteArray(sBytes);
        if (!s.modPow(publicExponent, n).equals(m))
        {
            throw new CryptoException("signing failure");
        }

        return BigIntegers.asUnsignedByteArray(modulusLen, s);
    }
}
