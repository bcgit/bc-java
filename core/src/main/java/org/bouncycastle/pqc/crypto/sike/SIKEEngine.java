package org.bouncycastle.pqc.crypto.sike;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;

class SIKEEngine
{
    private SecureRandom random;

    protected Internal params;
    protected Isogeny isogeny;
    protected Fpx fpx;
    private SIDH sidh;

    public int getDefaultSessionKeySize()
    {
        return params.MSG_BYTES * 8;
    }

    public int getCipherTextSize()
    {
        return params.CRYPTO_CIPHERTEXTBYTES;
    }

    public int getPrivateKeySize()
    {
        return params.CRYPTO_SECRETKEYBYTES;
    }

    public int getPublicKeySize()
    {
        return params.CRYPTO_PUBLICKEYBYTES;
    }

    public SIKEEngine(int ver, SecureRandom random)
    {
        this.random = random;
        //todo switch for different parameters
        switch (ver)
        {
        case 434:
            params = new P434(false);
            break;
        case 503:
            params = new P503(false);
            break;
        case 610:
            params = new P610(false);
            break;
        case 751:
            params = new P751(false);
            break;
        default:
            break;

        }
        fpx = new Fpx(this);
        isogeny = new Isogeny(this);
        sidh = new SIDH(this);
    }

    // SIKE's key generation
    // Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          public key pk (CRYPTO_PUBLICKEYBYTES bytes)
    public int crypto_kem_keypair(byte[] pk, byte[] sk, SecureRandom random)
    {
        byte[] s = new byte[params.MSG_BYTES];
        random.nextBytes(s);

        // Generation of Bob's secret key
        // Outputs random value in [0, 2^Floor(Log(2, oB)) - 1]
        // todo/org: SIDH.random_mod_order_B(sk, random);
        byte[] random_digits = new byte[params.SECRETKEY_B_BYTES];
        random.nextBytes(random_digits);
        random_digits[params.SECRETKEY_B_BYTES - 1] &= params.MASK_BOB;

        System.arraycopy(s, 0, sk, 0, params.MSG_BYTES);
        System.arraycopy(random_digits, 0, sk, params.MSG_BYTES, params.SECRETKEY_B_BYTES);
        ///

        sidh.EphemeralKeyGeneration_B(sk, pk);

        // Append public key pk to secret key sk
        System.arraycopy(pk, 0, sk, params.MSG_BYTES + params.SECRETKEY_B_BYTES, params.CRYPTO_PUBLICKEYBYTES);

        return 0;
    }

    // SIKE's encapsulation
    // Input:   public key pk         (CRYPTO_PUBLICKEYBYTES bytes)
    // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
    public int crypto_kem_enc(byte[] ct, byte[] ss, byte[] pk, SecureRandom random)
    {
        byte[] ephemeralsk = new byte[params.SECRETKEY_A_BYTES];
        byte[] jinvariant = new byte[params.FP2_ENCODED_BYTES];
        byte[] h = new byte[params.MSG_BYTES];
        byte[] temp = new byte[params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES];

        // Generate ephemeralsk <- G(m||pk) mod oA
        byte[] tmp = new byte[params.MSG_BYTES]; // todo: is there a simplier way to do this?
        random.nextBytes(tmp);
        System.arraycopy(tmp, 0, temp, 0, params.MSG_BYTES);
        System.arraycopy(pk, 0, temp, params.MSG_BYTES, params.CRYPTO_PUBLICKEYBYTES);

        Xof digest = new SHAKEDigest(256);
        digest.update(temp, 0, params.CRYPTO_PUBLICKEYBYTES + params.MSG_BYTES);
        digest.doFinal(ephemeralsk, 0, params.SECRETKEY_A_BYTES);
        ephemeralsk[params.SECRETKEY_A_BYTES - 1] &= params.MASK_ALICE;

        // Encrypt
        sidh.EphemeralKeyGeneration_A(ephemeralsk, ct);
        sidh.EphemeralSecretAgreement_A(ephemeralsk, pk, jinvariant);

        digest.update(jinvariant, 0, params.FP2_ENCODED_BYTES);
        digest.doFinal(h, 0, params.MSG_BYTES);

        for (int i = 0; i < params.MSG_BYTES; i++)
        {
            ct[i + params.CRYPTO_PUBLICKEYBYTES] = (byte)(temp[i] ^ h[i]);
        }

        // Generate shared secret ss <- H(m||ct)
        System.arraycopy(ct, 0, temp, params.MSG_BYTES, params.CRYPTO_CIPHERTEXTBYTES);

        digest.update(temp, 0, params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES);
        digest.doFinal(ss, 0, params.CRYPTO_BYTES);

        return 0;
    }

    // SIKE's decapsulation
    // Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
    // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    public int crypto_kem_dec(byte[] ss, byte[] ct, byte[] sk)
    {
        byte[] ephemeralsk_ = new byte[params.SECRETKEY_A_BYTES];
        byte[] jinvariant_ = new byte[params.FP2_ENCODED_BYTES];
        byte[] h_ = new byte[params.MSG_BYTES];
        byte[] c0_ = new byte[params.CRYPTO_PUBLICKEYBYTES];
        byte[] temp = new byte[params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES];

        // Decrypt
        // int EphemeralSecretAgreement_B(PrivateKeyB, PublicKeyA, SharedSecretB)
        sidh.EphemeralSecretAgreement_B(sk, ct, jinvariant_);

        Xof digest = new SHAKEDigest(256);
        digest.update(jinvariant_, 0, params.FP2_ENCODED_BYTES);
        digest.doFinal(h_, 0, params.MSG_BYTES);
        for (int i = 0; i < params.MSG_BYTES; i++)
        {
            temp[i] = (byte)(ct[i + params.CRYPTO_PUBLICKEYBYTES] ^ h_[i]);
        }

        // Generate ephemeralsk_ <- G(m||pk) mod oA
        System.arraycopy(sk, params.MSG_BYTES + params.SECRETKEY_B_BYTES, temp, params.MSG_BYTES, params.CRYPTO_PUBLICKEYBYTES);

        digest.update(temp, 0, params.CRYPTO_PUBLICKEYBYTES + params.MSG_BYTES);
        digest.doFinal(ephemeralsk_, 0, params.SECRETKEY_A_BYTES);
        ephemeralsk_[params.SECRETKEY_A_BYTES - 1] &= params.MASK_ALICE;


        // Generate shared secret ss <- H(m||ct), or output ss <- H(s||ct) in case of ct verification failure
        sidh.EphemeralKeyGeneration_A(ephemeralsk_, c0_);

        // If selector = 0 then do ss = H(m||ct), else if selector = -1 load s to do ss = H(s||ct)
        byte selector = fpx.ct_compare(c0_, ct, params.CRYPTO_PUBLICKEYBYTES);
        fpx.ct_cmov(temp, sk, params.MSG_BYTES, selector);

        System.arraycopy(ct, 0, temp, params.MSG_BYTES, params.CRYPTO_CIPHERTEXTBYTES);
        digest.update(temp, 0, params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES);
        digest.doFinal(ss, 0, params.CRYPTO_BYTES);

        return 0;
    }

}
