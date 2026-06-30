package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSABlindSignatureParameters;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Client side of the RSA Blind Signature Scheme with Appendix (RSABSSA) defined
 * in RFC 9474. A single {@link #blind} call performs both {@code Prepare}
 * (sec. 4.1) and {@code Blind} (sec. 4.2); {@link #finalize(Blinded, byte[])}
 * performs {@code Finalize} (sec. 4.4). The {@code BlindSign} server step lives
 * in {@link RSABlindSignatureServer} and the variant choices in
 * {@link RSABlindSignatureParameters}.
 * <p>
 * The client side is therefore two calls — {@code blind} then {@code finalize} —
 * with the server's {@code BlindSign} in between:
 * <pre>{@code
 * RSABlindSignatureClient client = new RSABlindSignatureClient(
 *     RSABlindSignatureParameters.RSABSSA_SHA384_PSS_RANDOMIZED, publicKey);
 *
 * RSABlindSignatureClient.Blinded blinded = client.blind(msg);
 *
 * // send blinded.getBlindedMessage() to the server; receive blind_sig
 *
 * byte[] sig = client.finalize(blinded, blindSig);
 * // (blinded.getPreparedMessage(), sig) is the RSASSA-PSS pair verifiers check
 * }</pre>
 * The {@link SecureRandom} used for the prepare prefix, the EMSA-PSS salt, and
 * the blinding factor is supplied at construction; the
 * {@code (parameters, publicKey)} convenience constructor uses the
 * {@link CryptoServicesRegistrar} default.
 * <p>
 * {@code Blind} is expressed on the existing BC RSA blinding toolkit —
 * {@link RSABlindingFactorGenerator}, {@link RSABlindingParameters} and
 * {@link PSSSigner} driven by an {@link RSABlindingEngine} — the same
 * composition {@code PSSBlindTest} uses for Chaum RSA-PSS blind signing.
 * <p>
 * Each request's state is carried by the returned {@link Blinded} (the blinded
 * message, the prepared message, and the secret unblinding value), so a single
 * instance is reusable across requests.
 * <p>
 * For randomised variants the resulting signature is over a prepared message
 * that prepends a fresh 32-byte prefix to {@code msg} (RFC 9474 sec. 4.1); that
 * prepared message — {@link Blinded#getPreparedMessage()} — is what downstream
 * verifiers check the signature against, not the original {@code msg}.
 */
public class RSABlindSignatureClient
{
    private final RSABlindSignatureParameters parameters;
    private final RSAKeyParameters publicKey;
    private final int modulusLen;
    private final SecureRandom random;

    /**
     * Equivalent to {@link #RSABlindSignatureClient(RSABlindSignatureParameters, RSAKeyParameters, SecureRandom)}
     * with a {@link SecureRandom} obtained from {@link CryptoServicesRegistrar}.
     *
     * @param parameters the RFC 9474 sec. 5 variant.
     * @param publicKey  the server's RSA public key.
     */
    public RSABlindSignatureClient(RSABlindSignatureParameters parameters, RSAKeyParameters publicKey)
    {
        this(parameters, publicKey, CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * @param parameters the RFC 9474 sec. 5 variant.
     * @param publicKey  the server's RSA public key.
     * @param random     source of randomness for the prepare prefix (randomised
     *                   variants), the EMSA-PSS salt, and the blinding factor;
     *                   must not be {@code null} — use
     *                   {@link #RSABlindSignatureClient(RSABlindSignatureParameters, RSAKeyParameters)}
     *                   for the {@link CryptoServicesRegistrar} default.
     */
    public RSABlindSignatureClient(RSABlindSignatureParameters parameters, RSAKeyParameters publicKey, SecureRandom random)
    {
        if (parameters == null)
        {
            throw new NullPointerException("'parameters' cannot be null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("'publicKey' cannot be null");
        }
        if (random == null)
        {
            throw new NullPointerException("'random' cannot be null");
        }
        if (publicKey.isPrivate())
        {
            throw new IllegalArgumentException("RSA parameters should be for a public key");
        }

        this.parameters = parameters;
        this.publicKey = publicKey;
        this.modulusLen = BigIntegers.getUnsignedByteLength(publicKey.getModulus());
        this.random = random;
    }

    /**
     * RFC 9474 {@code Prepare} (sec. 4.1) followed by {@code Blind} (sec. 4.2):
     * prepare {@code msg} (prepend a fresh 32-byte prefix for randomised
     * variants, identity otherwise), EMSA-PSS encode it, draw an invertible
     * blinding factor {@code r}, and blind the encoding to
     * {@code z = encoded_msg * r^e mod n}. The returned {@link Blinded} carries
     * the prepared message, the {@code blinded_msg} to send to the server, and
     * the secret unblinding value for {@link #finalize(Blinded, byte[])}.
     *
     * @param msg the application message to be signed.
     * @throws CryptoException if EMSA-PSS encoding fails (e.g. the modulus is too
     *                         small for the variant's hash/salt lengths) or the
     *                         encoded message is not coprime with the modulus.
     */
    public Blinded blind(byte[] msg)
        throws CryptoException
    {
        if (msg == null)
        {
            throw new NullPointerException("'msg' cannot be null");
        }

        BigInteger n = publicKey.getModulus();

        byte[] preparedMsg = prepare(msg);

        // Draw the blinding factor through the canonical RSA blinding-factor generator
        // (the same primitive PSSBlindTest and the Chaum RSA-PSS path use); it already
        // enforces gcd(r, n) == 1.
        RSABlindingFactorGenerator factorGenerator = new RSABlindingFactorGenerator();
        factorGenerator.init(new ParametersWithRandom(publicKey, random));
        BigInteger r = factorGenerator.generateBlindingFactor();

        // EMSA-PSS encode then multiply by r^e mod n in a single step: PSSSigner builds
        // the encoded block and RSABlindingEngine (its cipher, in encrypt mode) applies
        // the Chaum blinding. For PSS variants PSSSigner draws the salt from random; for
        // PSSZERO the salt length is zero and no salt is drawn.
        PSSSigner blindEncoder = new PSSSigner(new RSABlindingEngine(), parameters.createDigest(),
            parameters.getSaltLength());
        blindEncoder.init(true, new ParametersWithRandom(new RSABlindingParameters(publicKey, r), random));
        blindEncoder.update(preparedMsg, 0, preparedMsg.length);
        byte[] blindedMsg = blindEncoder.generateSignature();

        // RFC 9474 sec. 4.2 step 4-5: reject an encoded message not coprime with n.
        // Because r (hence r^e) is coprime with n, gcd(blindedMsg, n) == gcd(encoded_msg, n),
        // so the check applies equally to the blinded value.
        if (!BigIntegers.fromUnsignedByteArray(blindedMsg).gcd(n).equals(BigInteger.ONE))
        {
            throw new CryptoException("invalid input");
        }

        return new Blinded(blindedMsg, preparedMsg, BigIntegers.modOddInverse(n, r));
    }

    /**
     * RFC 9474 {@code Finalize} (sec. 4.4): unblind the server's signature for
     * the supplied {@link Blinded} request and verify it as a standard
     * RSASSA-PSS signature over the prepared message.
     * <p>
     * The method name follows the RFC 9474 sec. 4.4 {@code Finalize} step; it is
     * an overload of {@link Object#finalize()} (distinct signature), not an override.
     *
     * @param blinded  the value returned by {@link #blind} for this request.
     * @param blindSig the {@code blind_sig} returned by the server.
     * @return the unblinded RSASSA-PSS signature; it verifies against
     *         {@code blinded.getPreparedMessage()}.
     * @throws CryptoException if {@code blindSig} has the wrong length or the
     *                         unblinded signature fails RSASSA-PSS verification.
     */
    public byte[] finalize(Blinded blinded, byte[] blindSig)
        throws CryptoException
    {
        if (blinded == null)
        {
            throw new NullPointerException("'blinded' cannot be null");
        }
        if (blindSig == null)
        {
            throw new NullPointerException("'blindSig' cannot be null");
        }
        if (blindSig.length != modulusLen)
        {
            throw new CryptoException("unexpected input size");
        }

        BigInteger n = publicKey.getModulus();
        BigInteger z = BigIntegers.fromUnsignedByteArray(blindSig);

        // Unblind: s = z * inv mod n. asUnsignedByteArray pads to modulus_len, so the
        // returned signature is always full length even when s has a leading zero byte.
        byte[] sig = BigIntegers.asUnsignedByteArray(modulusLen, z.multiply(blinded.inverse).mod(n));

        // RFC 9474 sec. 4.4 step 5 / sec. 4.5: verify as a standard RSASSA-PSS signature
        // (RFC 8017 sec. 8.1.2 RSASSA-PSS-VERIFY) before returning, so a fault that
        // survived BlindSign is caught client-side too.
        PSSSigner verifier = new PSSSigner(new RSAEngine(), parameters.createDigest(), parameters.getSaltLength());
        verifier.init(false, publicKey);
        verifier.update(blinded.preparedMessage, 0, blinded.preparedMessage.length);
        if (!verifier.verifySignature(sig))
        {
            throw new CryptoException("invalid signature");
        }

        return sig;
    }

    private byte[] prepare(byte[] msg)
    {
        if (!parameters.isRandomized())
        {
            return Arrays.clone(msg);
        }

        byte[] prefix = new byte[RSABlindSignatureParameters.RANDOMIZED_PREFIX_LEN];
        random.nextBytes(prefix);
        return Arrays.concatenate(prefix, msg);
    }

    /**
     * Output of {@link RSABlindSignatureClient#blind}.
     * {@link #getBlindedMessage()} is sent to the server;
     * {@link #getPreparedMessage()} is the message the resulting signature is
     * over. The instance is passed back to
     * {@link RSABlindSignatureClient#finalize(Blinded, byte[])}, which uses the
     * carried prepared message and the secret unblinding value (the latter is
     * not exposed).
     */
    public static final class Blinded
    {
        private final byte[] blindedMessage;
        private final byte[] preparedMessage;
        private final BigInteger inverse;

        Blinded(byte[] blindedMessage, byte[] preparedMessage, BigInteger inverse)
        {
            this.blindedMessage = blindedMessage;
            this.preparedMessage = preparedMessage;
            this.inverse = inverse;
        }

        public byte[] getBlindedMessage()
        {
            return Arrays.clone(blindedMessage);
        }

        public byte[] getPreparedMessage()
        {
            return Arrays.clone(preparedMessage);
        }
    }
}
