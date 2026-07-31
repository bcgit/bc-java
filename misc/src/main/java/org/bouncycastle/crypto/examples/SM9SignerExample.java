package org.bouncycastle.crypto.examples;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.SM9SigMasterKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.crypto.signers.SM9Signer;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of the SM9 identity-based signature algorithm (GM/T 0044.2-2016) through the
 * lightweight API: a user signs with the private key the KGC derived for its identity,
 * and a verifier checks the signature knowing only the published signature master public
 * key and the signer's identity - no certificate is involved.
 * <p>
 * SM9 is identity-based: a trusted Key Generation Centre (KGC) holds the signature
 * master key pair ({@link SM9SigMasterKeyPairGenerator}) and derives each user's signing
 * key from the user's identity with {@code generateUserKey} (the key-extraction
 * operation - deterministic, and inherently escrowed: the KGC can derive every user's
 * key). The verifier supplies the master public key and the signer's identity as a
 * {@link ParametersWithID}. The signature produced here is the raw 97-byte h || S form;
 * the JCA {@code Signature.SM9} emits the same values as the GM/T 0080-2020 DER
 * structure instead.
 */
public class SM9SignerExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // 1. KGC: generate the SM9 signature master key pair and derive Alice's
        //    signing key from her identity (hid = 0x01 is applied internally).
        SM9SigMasterKeyPairGenerator kpGen = new SM9SigMasterKeyPairGenerator();
        kpGen.init(new KeyGenerationParameters(random, 256));
        AsymmetricCipherKeyPair master = kpGen.generateKeyPair();
        SM9SigMasterPrivateKeyParameters masterPriv = (SM9SigMasterPrivateKeyParameters)master.getPrivate();
        SM9SigMasterPublicKeyParameters masterPub = (SM9SigMasterPublicKeyParameters)master.getPublic();

        byte[] aliceIdentity = Strings.toByteArray("Alice");
        SM9SigPrivateKeyParameters aliceKey = masterPriv.generateUserKey(aliceIdentity);

        // 2. Alice: sign the message with her identity key.
        byte[] message = Strings.toByteArray("Chinese IBS standard");

        SM9Signer signer = new SM9Signer();
        signer.init(true, new ParametersWithRandom(aliceKey, random));
        signer.update(message, 0, message.length);
        byte[] signature = signer.generateSignature();

        // 3. Verifier: check against the published master public key and Alice's
        //    identity alone - no certificate or KGC interaction needed.
        SM9Signer verifier = new SM9Signer();
        verifier.init(false, new ParametersWithID(masterPub, aliceIdentity));
        verifier.update(message, 0, message.length);
        if (!verifier.verifySignature(signature))
        {
            throw new IllegalStateException("SM9 signature failed to verify");
        }

        System.out.println("SM9 signature (h || S, " + signature.length + " bytes): "
            + Hex.toHexString(signature));
        System.out.println("verified for \"Alice\" against the master public key + identity.");
    }
}
