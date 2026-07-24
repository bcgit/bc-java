package org.bouncycastle.jcajce.examples;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jcajce.interfaces.SM9SignMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9SignMasterPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of the SM9 identity-based signature algorithm (GM/T 0044.2-2016) through the
 * BouncyCastle provider's {@code Signature.SM9}: a user signs with the private key
 * derived for its identity, and a verifier checks against the signer's public key.
 * <p>
 * SM9 is identity-based: a trusted Key Generation Centre (KGC) holds a signature master
 * key pair and derives each user's key pair from the user's identity - so there are no
 * certificates, and a verifier forms the signer's public key from the published master
 * public key and the signer's identity alone, via
 * {@link SM9SignMasterPublicKey#getUserPublicKey(byte[])}. The master key pair comes from
 * {@code KeyPairGenerator.SM9-SIGN}; a user's key pair is derived from the master private
 * key via {@link SM9SignMasterPrivateKey#generateUserKeyPair(byte[])} (the KGC
 * key-extraction operation). The model carries inherent key escrow (the KGC can derive
 * every user's key), so the KGC must be trusted accordingly.
 * <p>
 * The signature is the GM/T 0080-2020 SM9Signature structure (DER: h, S).
 */
public class SM9SignExample
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        // 1. KGC: generate the SM9 signature master key pair.
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-SIGN", "BC");
        kpGen.initialize(256, random);
        KeyPair master = kpGen.generateKeyPair();

        // 2. KGC: derive Alice's key pair from her identity (deterministic); Alice signs
        //    with the private half.
        byte[] aliceId = Strings.toByteArray("Alice");
        KeyPair alice = ((SM9SignMasterPrivateKey)master.getPrivate()).generateUserKeyPair(aliceId);

        byte[] message = Strings.toByteArray("Chinese IBS standard");

        Signature signer = Signature.getInstance("SM9", "BC");
        signer.initSign(alice.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        // 3. Verifier: form Alice's public key from the published master public key and
        //    her identity - no certificate or KGC interaction needed - and verify.
        Signature verifier = Signature.getInstance("SM9", "BC");
        verifier.initVerify(((SM9SignMasterPublicKey)master.getPublic()).getUserPublicKey(aliceId));
        verifier.update(message);
        if (!verifier.verify(signature))
        {
            throw new IllegalStateException("SM9 signature failed to verify");
        }

        System.out.println("SM9 signature (DER, " + signature.length + " bytes): "
            + Hex.toHexString(signature));
        System.out.println("verified for \"Alice\" against the master public key + identity.");
    }
}
