package org.bouncycastle.crypto.examples;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSABlindSignatureParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSABlindSignatureClient;
import org.bouncycastle.crypto.signers.RSABlindSignatureServer;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example: an RFC 9474 RSA Blind Signature (RSABSSA) exchange using BC's lightweight crypto API.
 * <p>
 * RFC 9474 — <a href="https://www.rfc-editor.org/rfc/rfc9474.html">RSA Blind Signatures</a> — lets a
 * client obtain a signature over a message the signer never sees: the client blinds an EMSA-PSS encoding,
 * the server signs the blinded value, and the client unblinds the result into an ordinary RSASSA-PSS
 * signature that anyone can verify with the standard PKCS#1 v2.2 PSS path. It is the building block for
 * unlinkable authentication tokens.
 * <p>
 * In this example the client ({@link RSABlindSignatureClient}) and the server
 * ({@link RSABlindSignatureServer}) run in the same JVM; in a real deployment they would be in different
 * locations, exchanging only {@code blinded_msg} and {@code blind_sig} over the network — the message
 * itself never leaves the client.
 * <p>
 * Run with {@code java -cp <bcprov-jar> org.bouncycastle.crypto.examples.RSABlindSignatureExample}; no
 * provider registration is needed because everything goes through the lightweight API directly.
 */
public class RSABlindSignatureExample
{
    public static void main(String[] args)
        throws CryptoException
    {
        SecureRandom random = new SecureRandom();

        // The server holds an RSA key pair; the client is given only the public key.
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 2048, 100));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        RSAPrivateCrtKeyParameters serverKey = (RSAPrivateCrtKeyParameters)kp.getPrivate();
        RSAKeyParameters publicKey = (RSAKeyParameters)kp.getPublic();

        // Both sides agree on a variant. The randomized variants are RECOMMENDED (RFC 9474 sec. 5).
        RSABlindSignatureParameters variant = RSABlindSignatureParameters.RSABSSA_SHA384_PSS_RANDOMIZED;

        byte[] msg = "one anonymous token".getBytes();

        RSABlindSignatureClient client = new RSABlindSignatureClient(variant, publicKey, random);
        RSABlindSignatureServer server = new RSABlindSignatureServer(serverKey);

        System.out.println("variant:                        " + variant.getName());
        System.out.println("message:                        " + new String(msg));

        // 1. Blind (RFC 9474 sec. 4.1-4.2): prepare msg (prepend a fresh 32-byte prefix for the
        //    randomized variant) and blind it in one call. The returned Blinded carries the prepared
        //    message and the secret unblinding value; only blinded_msg is sent to the server.
        RSABlindSignatureClient.Blinded blinded = client.blind(msg);
        System.out.println("client -> server (blinded_msg): " + Hex.toHexString(blinded.getBlindedMessage()));

        // 2. BlindSign (sec. 4.3): the server signs the blinded value it cannot read, after the
        //    mandated RSAVP1 self-check that catches CRT faults before the value leaves the server.
        byte[] blindSig = server.blindSign(blinded.getBlindedMessage());
        System.out.println("server -> client (blind_sig):   " + Hex.toHexString(blindSig));

        // 3. Finalize (sec. 4.4): the client unblinds into a standard RSASSA-PSS signature.
        byte[] sig = client.finalize(blinded, blindSig);
        System.out.println("unblinded signature:            " + Hex.toHexString(sig));

        // The signature is over the PREPARED message (msg with its random prefix), not the raw msg:
        // verify (preparedMsg, sig) with a vanilla PSSSigner, exactly as any RFC 8017 verifier would
        // (RFC 9474 sec. 4.5).
        byte[] preparedMsg = blinded.getPreparedMessage();
        PSSSigner verifier = new PSSSigner(new RSAEngine(), variant.createDigest(), variant.getSaltLength());
        verifier.init(false, publicKey);
        verifier.update(preparedMsg, 0, preparedMsg.length);
        boolean ok = verifier.verifySignature(sig);

        System.out.println("verifies as RSASSA-PSS:         " + ok);
        System.out.println(ok ? "Success" : "Failure");
    }

    private RSABlindSignatureExample()
    {
    }
}
