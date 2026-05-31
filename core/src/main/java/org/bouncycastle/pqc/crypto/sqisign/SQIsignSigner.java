package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

/**
 * SQIsign signer. Wired for all three NIST parameter sets (lvl1/lvl3/lvl5)
 * via the polymorphic GfField-based dispatch in the EC/HD/theta layer.
 * <p>
 * <b>Side-channel note:</b> signing is <em>not</em> constant-time. SQIsign's
 * arithmetic is implemented over {@link java.math.BigInteger} throughout — the
 * GF(p) / GF(p&sup2;) base-field and elliptic-curve layer as well as the
 * secret-key-dependent quaternion / ideal / lattice layer (commitment,
 * challenge ideal, response sampling and the auxiliary isogeny). BigInteger
 * operations are inherently variable-time, and the signing path additionally
 * contains secret-dependent rejection loops and variable-iteration Euclidean /
 * lattice-reduction (LLL, HNF, Cornacchia) steps. This matches the SQIsign
 * reference implementation, whose KLPT / Clapotis layer is likewise
 * variable-time. No constant-time guarantee can be made for signing or key
 * generation; verification operates only on public values.
 * </p>
 * <p>
 * <b>Deployment guidance:</b> the long-term private key participates in the
 * variable-time response / ideal-to-isogeny computation, so per-signature
 * timing depends on secret material and can in principle accumulate toward the
 * static key over many signatures. SQIsign signing therefore should not be
 * exposed in settings where an adversary can measure the timing of signing
 * operations performed under the same key — e.g. a remote timing oracle that
 * signs attacker-influenced messages on demand, or a co-located / shared-host
 * environment open to micro-architectural timing observation. This is an
 * algorithmic property of SQIsign (the reference implementation shares it), not
 * a limitation specific to this port, and there is no known practical
 * constant-time formulation of the KLPT / lattice steps; treat it as a usage
 * constraint until constant-time SQIsign techniques mature.
 * </p>
 */
public class SQIsignSigner
    implements MessageSigner
{
    private SQIsignParameters params;
    private SQIsignPublicKeyParameters pubKey;
    private SQIsignPrivateKeyParameters privKey;
    private SecureRandom random;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (SQIsignPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (SQIsignPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (SQIsignPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        if (privKey == null)
        {
            throw new IllegalStateException("SQIsign signer not initialized for signing");
        }
        if (params == SQIsignParameters.sqisign_lvl1)
        {
            return signLvl1(message);
        }
        if (params == SQIsignParameters.sqisign_lvl3)
        {
            return signLvl3(message);
        }
        if (params == SQIsignParameters.sqisign_lvl5)
        {
            return signLvl5(message);
        }
        throw new IllegalStateException("Unknown SQIsign parameter set: " + params);
    }

    private byte[] signLvl1(byte[] message)
    {
        SQIsignPublicKeyData pk = new SQIsignPublicKeyData();
        SQIsignSecretKeyData sk = SQIsignEncodeLvl1.secretKeyFromBytesFull(
            privKey.getPrivateKey(), 0, pk);

        SQIsignSignatureLvl1 sig = new SQIsignSignatureLvl1();
        int ok = SQIsignSignLvl1.protocolsSign(sig, pk.curve, sk, message, random);
        if (ok != 1)
        {
            throw new IllegalStateException("SQIsign sign: protocols_sign failed");
        }
        return org.bouncycastle.util.Arrays.concatenate(
            SQIsignEncodeLvl1.signatureToBytes(sig), message);
    }

    private byte[] signLvl3(byte[] message)
    {
        SQIsignPublicKeyData pk = new SQIsignPublicKeyData();
        SQIsignSecretKeyData sk = SQIsignEncodeLvl3.secretKeyFromBytesFull(
            privKey.getPrivateKey(), 0, pk);

        SQIsignSignatureLvl3 sig = new SQIsignSignatureLvl3();
        int ok = SQIsignSignLvl3.protocolsSign(sig, pk.curve, sk, message, random);
        if (ok != 1)
        {
            throw new IllegalStateException("SQIsign sign: protocols_sign failed");
        }
        return org.bouncycastle.util.Arrays.concatenate(
            SQIsignEncodeLvl3.signatureToBytes(sig), message);
    }

    private byte[] signLvl5(byte[] message)
    {
        SQIsignPublicKeyData pk = new SQIsignPublicKeyData();
        SQIsignSecretKeyData sk = SQIsignEncodeLvl5.secretKeyFromBytesFull(
            privKey.getPrivateKey(), 0, pk);

        SQIsignSignatureLvl5 sig = new SQIsignSignatureLvl5();
        int ok = SQIsignSignLvl5.protocolsSign(sig, pk.curve, sk, message, random);
        if (ok != 1)
        {
            throw new IllegalStateException("SQIsign sign: protocols_sign failed");
        }
        return org.bouncycastle.util.Arrays.concatenate(
            SQIsignEncodeLvl5.signatureToBytes(sig), message);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (pubKey == null)
        {
            throw new IllegalStateException("SQIsign signer not initialized for verification");
        }
        if (params == SQIsignParameters.sqisign_lvl1)
        {
            return verifyLvl1(message, signature);
        }
        if (params == SQIsignParameters.sqisign_lvl3)
        {
            return verifyLvl3(message, signature);
        }
        if (params == SQIsignParameters.sqisign_lvl5)
        {
            return verifyLvl5(message, signature);
        }
        throw new IllegalStateException("Unknown SQIsign parameter set: " + params);
    }

    private boolean verifyLvl1(byte[] message, byte[] signature)
    {
        if (signature == null || signature.length < SQIsignEncodeLvl1.SIGNATURE_BYTES)
        {
            return false;
        }
        SQIsignPublicKeyData pk = SQIsignEncodeLvl1.publicKeyFromBytes(pubKey.getPublicKey());
        SQIsignSignatureLvl1 sig;
        try
        {
            // The first SIGNATURE_BYTES are the signature; any trailing bytes
            // (e.g. the appended message in NIST "sm" format) are ignored.
            sig = SQIsignEncodeLvl1.signatureFromBytes(signature);
        }
        catch (IllegalArgumentException e)
        {
            return false;
        }
        try
        {
            return SQIsignVerifyLvl1.protocolsVerify(sig, pk.curve, pk.hintPk, message) == 1;
        }
        catch (RuntimeException e)
        {
            return false;
        }
    }

    private boolean verifyLvl3(byte[] message, byte[] signature)
    {
        if (signature == null || signature.length < SQIsignEncodeLvl3.SIGNATURE_BYTES)
        {
            return false;
        }
        SQIsignPublicKeyData pk = SQIsignEncodeLvl3.publicKeyFromBytes(pubKey.getPublicKey());
        SQIsignSignatureLvl3 sig;
        try
        {
            sig = SQIsignEncodeLvl3.signatureFromBytes(signature);
        }
        catch (IllegalArgumentException e)
        {
            return false;
        }
        try
        {
            return SQIsignVerifyLvl3.protocolsVerify(sig, pk.curve, pk.hintPk, message) == 1;
        }
        catch (RuntimeException e)
        {
            return false;
        }
    }

    private boolean verifyLvl5(byte[] message, byte[] signature)
    {
        if (signature == null || signature.length < SQIsignEncodeLvl5.SIGNATURE_BYTES)
        {
            return false;
        }
        SQIsignPublicKeyData pk = SQIsignEncodeLvl5.publicKeyFromBytes(pubKey.getPublicKey());
        SQIsignSignatureLvl5 sig;
        try
        {
            sig = SQIsignEncodeLvl5.signatureFromBytes(signature);
        }
        catch (IllegalArgumentException e)
        {
            return false;
        }
        try
        {
            return SQIsignVerifyLvl5.protocolsVerify(sig, pk.curve, pk.hintPk, message) == 1;
        }
        catch (RuntimeException e)
        {
            return false;
        }
    }
}
