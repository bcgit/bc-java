package org.bouncycastle.crypto.examples;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.BIP340Signer;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example: produce and verify a BIP-340 Schnorr signature over secp256k1 using BC's lightweight crypto API.
 * <p>
 * BIP-340 — <a href="https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki">Schnorr Signatures for
 * secp256k1</a> — is what Bitcoin Taproot uses for on-chain signatures. The public-key encoding is a 32-byte
 * x-only point (no SEC1 02/03 prefix) and the signature encoding is a fixed 64-byte concatenation
 * {@code r || s}; neither matches BC's ECDSA defaults, so the relevant byte-level conversions are shown inline.
 * <p>
 * Run with {@code java -cp <bcprov-jar> org.bouncycastle.crypto.examples.BIP340SignerExample}; no provider
 * registration is needed because everything goes through the lightweight API directly.
 */
public class BIP340SignerExample
{
    public static void main(String[] args)
    {
        SecureRandom random = new SecureRandom();

        ECKeyPairGenerator kpg = new ECKeyPairGenerator();
        kpg.init(new ECKeyGenerationParameters(BIP340Signer.getDomain(), random));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)kp.getPrivate();
        ECPublicKeyParameters pub = (ECPublicKeyParameters)kp.getPublic();

        byte[] xOnlyPub = BigIntegers.asUnsignedByteArray(32,
            pub.getQ().normalize().getAffineXCoord().toBigInteger());

        byte[] message = "BIP-340 demo".getBytes();

        BIP340Signer signer = new BIP340Signer();
        signer.init(true, new ParametersWithRandom(priv, random));
        signer.update(message, 0, message.length);
        byte[] signature = signer.generateSignature();

        BIP340Signer verifier = new BIP340Signer();
        verifier.init(false, BIP340Signer.decodePublicKey(xOnlyPub));
        verifier.update(message, 0, message.length);
        boolean ok = verifier.verifySignature(signature);

        System.out.println("public key (x-only): " + Hex.toHexString(xOnlyPub));
        System.out.println("signature:           " + Hex.toHexString(signature));
        System.out.println("verifies:            " + ok);
    }

    private BIP340SignerExample()
    {
    }
}
