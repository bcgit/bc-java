package org.bouncycastle.crypto.examples;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.util.Strings;

/**
 * Example: RSA-PSS signing and verification when the caller already holds a
 * <b>pre-computed</b> message hash (mHash) rather than the message itself.
 * <p>
 * RFC 8017 (PKCS#1 v2.2) sec. 9.1 EMSA-PSS hashes the message M to mHash, then
 * salts and re-hashes. {@link PSSSigner#createRawSigner(org.bouncycastle.crypto.AsymmetricBlockCipher, org.bouncycastle.crypto.Digest)}
 * replaces only that first hash with a length-validating pass-through, so a
 * caller that has already computed mHash (e.g. it was streamed/hashed elsewhere,
 * or produced by a smart card) can feed mHash directly through {@code update(...)}
 * while the signer performs the remaining salt / M' / second-hash / masking steps.
 * This is the lightweight-API equivalent of a "sign pre-computed hash" entry point
 * (github #1145).
 * <p>
 * The example signs a pre-computed SHA-256 hash with the raw signer and then shows
 * that the resulting signature is an ordinary RSA-PSS signature: it verifies both
 * with the raw verifier (fed the same mHash) and with a standard {@link PSSSigner}
 * fed the full message.
 */
public class RSAPSSPreComputedHashExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // an RSA key pair via the lightweight API
        RSAKeyPairGenerator kpGen = new RSAKeyPairGenerator();
        kpGen.init(new RSAKeyGenerationParameters(
            BigInteger.valueOf(0x10001), random, 2048, 100));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        RSAKeyParameters privKey = (RSAKeyParameters)kp.getPrivate();
        RSAKeyParameters pubKey = (RSAKeyParameters)kp.getPublic();

        byte[] message = Strings.toByteArray("the message the signer never sees");

        // the caller computes the content hash itself - this is the value that
        // would normally arrive pre-computed from elsewhere
        SHA256Digest digest = new SHA256Digest();
        byte[] mHash = new byte[digest.getDigestSize()];
        digest.update(message, 0, message.length);
        digest.doFinal(mHash, 0);

        // sign the pre-computed hash: createRawSigner feeds mHash through a
        // Prehash pass-through instead of re-hashing the message. Exactly
        // digest.getDigestSize() bytes must be supplied, or generateSignature()
        // throws IllegalStateException("Incorrect prehash size").
        PSSSigner rawSigner = PSSSigner.createRawSigner(new RSAEngine(), new SHA256Digest());
        rawSigner.init(true, new ParametersWithRandom(privKey, random));
        rawSigner.update(mHash, 0, mHash.length);
        byte[] signature = rawSigner.generateSignature();

        // verify it the same way - again feeding the pre-computed hash
        PSSSigner rawVerifier = PSSSigner.createRawSigner(new RSAEngine(), new SHA256Digest());
        rawVerifier.init(false, pubKey);
        rawVerifier.update(mHash, 0, mHash.length);
        if (!rawVerifier.verifySignature(signature))
        {
            throw new IllegalStateException("pre-computed-hash verification failed");
        }

        // the signature is a standards-compliant RSA-PSS signature: an ordinary
        // PSSSigner fed the full message (same digest, salt length and trailer)
        // verifies it too. The random salt is recovered during verification, so
        // it need not be supplied.
        PSSSigner stdVerifier = new PSSSigner(new RSAEngine(), new SHA256Digest(), digest.getDigestSize());
        stdVerifier.init(false, pubKey);
        stdVerifier.update(message, 0, message.length);
        if (!stdVerifier.verifySignature(signature))
        {
            throw new IllegalStateException("standard PSS verification of pre-computed-hash signature failed");
        }

        System.out.println("pre-computed-hash RSA-PSS signature verified by both the raw and the standard verifier");
    }
}
