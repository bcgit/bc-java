package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * SQIsign key-pair generator wired for all three NIST parameter sets
 * (lvl1, lvl3, lvl5). The polymorphic GfField layer dispatches the EC/HD/theta
 * arithmetic to the per-level prime, and the per-level
 * {@code SQIsignKeyGenLvl*} drivers supply the precomp constants.
 */
public class SQIsignKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SQIsignParameters params;
    private SecureRandom random;
    private boolean initialized;

    public void init(KeyGenerationParameters param)
    {
        SQIsignKeyGenerationParameters p = (SQIsignKeyGenerationParameters)param;
        this.params = p.getParameters();
        this.random = p.getRandom();
        this.initialized = true;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        if (!initialized)
        {
            throw new IllegalStateException("SQIsign key pair generator not initialized");
        }

        if (params == SQIsignParameters.sqisign_lvl1)
        {
            return generateLvl1();
        }
        if (params == SQIsignParameters.sqisign_lvl3)
        {
            return generateLvl3();
        }
        if (params == SQIsignParameters.sqisign_lvl5)
        {
            return generateLvl5();
        }
        throw new IllegalStateException("Unknown SQIsign parameter set: " + params);
    }

    private AsymmetricCipherKeyPair generateLvl1()
    {
        SQIsignKeyGenLvl1.KeyPair kp = SQIsignKeyGenLvl1.protocolsKeygenFull(random);
        SQIsignPublicKeyData pk = new SQIsignPublicKeyData();
        org.bouncycastle.pqc.crypto.sqisign.EcCurve.copy(pk.curve, kp.sk.curve);
        pk.curve.isA24ComputedAndNormalized = false;
        pk.hintPk = kp.hintPk;

        byte[] pubBytes = SQIsignEncodeLvl1.publicKeyToBytes(pk);
        byte[] secBytes = SQIsignEncodeLvl1.secretKeyToBytes(
            kp.sk, pk, PrecompLvl1.QUATALG_PINFTY);
        return new AsymmetricCipherKeyPair(
            new SQIsignPublicKeyParameters(params, pubBytes),
            new SQIsignPrivateKeyParameters(params, secBytes));
    }

    private AsymmetricCipherKeyPair generateLvl3()
    {
        SQIsignKeyGenLvl3.KeyPair kp = SQIsignKeyGenLvl3.protocolsKeygenFull(random);
        SQIsignPublicKeyData pk = new SQIsignPublicKeyData();
        org.bouncycastle.pqc.crypto.sqisign.EcCurve.copy(pk.curve, kp.sk.curve);
        pk.curve.isA24ComputedAndNormalized = false;
        pk.hintPk = kp.hintPk;

        byte[] pubBytes = SQIsignEncodeLvl3.publicKeyToBytes(pk);
        byte[] secBytes = SQIsignEncodeLvl3.secretKeyToBytes(
            kp.sk, pk, QuatRepresentIntegerParamsLvl3.QUATALG_PINFTY);
        return new AsymmetricCipherKeyPair(
            new SQIsignPublicKeyParameters(params, pubBytes),
            new SQIsignPrivateKeyParameters(params, secBytes));
    }

    private AsymmetricCipherKeyPair generateLvl5()
    {
        SQIsignKeyGenLvl5.KeyPair kp = SQIsignKeyGenLvl5.protocolsKeygenFull(random);
        SQIsignPublicKeyData pk = new SQIsignPublicKeyData();
        org.bouncycastle.pqc.crypto.sqisign.EcCurve.copy(pk.curve, kp.sk.curve);
        pk.curve.isA24ComputedAndNormalized = false;
        pk.hintPk = kp.hintPk;

        byte[] pubBytes = SQIsignEncodeLvl5.publicKeyToBytes(pk);
        byte[] secBytes = SQIsignEncodeLvl5.secretKeyToBytes(
            kp.sk, pk, QuatRepresentIntegerParamsLvl5.QUATALG_PINFTY);
        return new AsymmetricCipherKeyPair(
            new SQIsignPublicKeyParameters(params, pubBytes),
            new SQIsignPrivateKeyParameters(params, secBytes));
    }
}
