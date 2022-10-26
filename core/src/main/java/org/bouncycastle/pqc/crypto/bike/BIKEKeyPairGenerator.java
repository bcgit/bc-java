package org.bouncycastle.pqc.crypto.bike;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class BIKEKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    // block length
    private int r;

    // the row weight
//    private int w;

    // Hamming weight of h0, h1
//    private int hw;

    // the error weight
//    private int t;

    //the shared secret size
    private int l;

    // number of iterations in BGF decoder
//    private int nbIter;

    // tau
//    private int tau;
    private int L_BYTE;
    private int R_BYTE;

    private BIKEKeyGenerationParameters bikeKeyGenerationParameters;

    @Override
    public void init(KeyGenerationParameters params)
    {
        this.bikeKeyGenerationParameters = (BIKEKeyGenerationParameters)params;
        this.random = params.getRandom();

        // get parameters
        this.r = this.bikeKeyGenerationParameters.getParameters().getR();
//        this.w = this.bikeKeyGenerationParameters.getParameters().getW();
        this.l = this.bikeKeyGenerationParameters.getParameters().getL();
//        this.t = this.bikeKeyGenerationParameters.getParameters().getT();
//        this.nbIter = this.bikeKeyGenerationParameters.getParameters().getNbIter();
//        this.tau = this.bikeKeyGenerationParameters.getParameters().getTau();
//        this.hw = w / 2;
        this.L_BYTE = l / 8;
        this.R_BYTE = (r + 7) / 8;
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        BIKEEngine engine = bikeKeyGenerationParameters.getParameters().getEngine();
        byte[] h0 = new byte[R_BYTE];
        byte[] h1 = new byte[R_BYTE];
        byte[] h = new byte[R_BYTE];
        byte[] sigma = new byte[L_BYTE];

        engine.genKeyPair(h0, h1, sigma, h, random);

        // form keys
        BIKEPublicKeyParameters publicKey = new BIKEPublicKeyParameters(bikeKeyGenerationParameters.getParameters(), h);
        BIKEPrivateKeyParameters privateKey = new BIKEPrivateKeyParameters(bikeKeyGenerationParameters.getParameters(), h0, h1, sigma);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }
}
