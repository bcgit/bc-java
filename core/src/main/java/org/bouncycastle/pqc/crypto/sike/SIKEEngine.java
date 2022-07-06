package org.bouncycastle.pqc.crypto.sike;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;

class SIKEEngine
{
    protected Internal params;
    protected Isogeny isogeny;
    protected Fpx fpx;
    private SIDH sidh;
    private SIDH_Compressed sidhCompressed;
    private boolean isCompressed;

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
    
    public SIKEEngine(int ver, boolean isCompressed)
    {
        this.isCompressed = isCompressed;
        switch(ver)
        {
            case 434:
                params = new P434(isCompressed);
                break;
            case 503:
                params = new P503(isCompressed);
                break;
            case 610:
                params = new P610(isCompressed);
                break;
            case 751:
                params = new P751(isCompressed);
                break;
            default:
                break;
                
        }
        fpx = new Fpx(this);
        isogeny = new Isogeny(this);
        if(isCompressed)
        {
            sidhCompressed = new SIDH_Compressed(this);
        }
        sidh = new SIDH(this);
    }

    // SIKE's key generation
    // Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          public key pk (CRYPTO_PUBLICKEYBYTES bytes)
    public int crypto_kem_keypair(byte[] pk, byte[] sk, SecureRandom random)
    {
        byte[] s = new byte[params.MSG_BYTES];
        random.nextBytes(s);



        if (isCompressed)
        {
            // Generation of Alice's secret key
            // Outputs random value in [0, 2^eA - 1]

            byte[] random_digits = new byte[params.SECRETKEY_A_BYTES];
            random.nextBytes(random_digits);
            random_digits[0] &= 0xFE;                            // Make private scalar even
            random_digits[params.SECRETKEY_A_BYTES-1] &= params.MASK_ALICE;    // Masking last byte

            System.arraycopy(s, 0, sk, 0, params.MSG_BYTES);
            System.arraycopy(random_digits, 0, sk, params.MSG_BYTES, params.SECRETKEY_A_BYTES);
            //

            sidhCompressed.EphemeralKeyGeneration_A_extended(sk, pk);
            System.arraycopy(pk, 0, sk, params.MSG_BYTES + params.SECRETKEY_A_BYTES, params.CRYPTO_PUBLICKEYBYTES);

        }
        else
        {
            // Generation of Bob's secret key
            // Outputs random value in [0, 2^Floor(Log(2, oB)) - 1]
            byte[] random_digits = new byte[params.SECRETKEY_B_BYTES];
            random.nextBytes(random_digits);
            random_digits[params.SECRETKEY_B_BYTES-1] &= params.MASK_BOB;

            System.arraycopy(s, 0, sk, 0, params.MSG_BYTES);
            System.arraycopy(random_digits, 0, sk, params.MSG_BYTES, params.SECRETKEY_B_BYTES);
            ///

            sidh.EphemeralKeyGeneration_B(sk, pk);
            System.arraycopy(pk, 0, sk, params.MSG_BYTES + params.SECRETKEY_B_BYTES, params.CRYPTO_PUBLICKEYBYTES);

        }
        // Append public key pk to secret key sk

        return 0;
    }

    // SIKE's encapsulation
    // Input:   public key pk         (CRYPTO_PUBLICKEYBYTES bytes)
    // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
    public int crypto_kem_enc(byte[] ct, byte[] ss, byte[] pk, SecureRandom random)
    {
        if(isCompressed)
        {
            byte[] ephemeralsk = new byte[params.SECRETKEY_B_BYTES];
            byte[] jinvariant = new byte[params.FP2_ENCODED_BYTES];
            byte[] h = new byte[params.MSG_BYTES];
            byte[] temp = new byte[params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES];

            // Generate ephemeralsk <- G(m||pk) mod oB
            byte[] tmp = new byte[params.MSG_BYTES];
            random.nextBytes(tmp);
            System.arraycopy(tmp, 0, temp, 0, params.MSG_BYTES);
            System.arraycopy(pk, 0, temp, params.MSG_BYTES, params.CRYPTO_PUBLICKEYBYTES);

            Xof digest = new SHAKEDigest(256);
            digest.update(temp, 0, params.CRYPTO_PUBLICKEYBYTES + params.MSG_BYTES);
            digest.doFinal(ephemeralsk, 0, params.SECRETKEY_B_BYTES);

            sidhCompressed.FormatPrivKey_B(ephemeralsk);

            // Encrypt
            sidhCompressed.EphemeralKeyGeneration_B_extended(ephemeralsk, ct, 1);
            sidhCompressed.EphemeralSecretAgreement_B(ephemeralsk, pk, jinvariant);

            digest.update(jinvariant, 0, params.FP2_ENCODED_BYTES);
            digest.doFinal(h, 0, params.MSG_BYTES);

            for (int i = 0; i < params.MSG_BYTES; i++)
            {
                ct[i + params.PARTIALLY_COMPRESSED_CHUNK_CT] = (byte) (temp[i] ^ h[i]);
            }

            // Generate shared secret ss <- H(m||ct)
            System.arraycopy(ct, 0, temp, params.MSG_BYTES, params.CRYPTO_CIPHERTEXTBYTES);

            digest.update(temp, 0, params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES);
            digest.doFinal(ss, 0, params.CRYPTO_BYTES);
            return 0;
        }
        else
        {
            byte[] ephemeralsk = new byte[params.SECRETKEY_A_BYTES];
            byte[] jinvariant = new byte[params.FP2_ENCODED_BYTES];
            byte[] h = new byte[params.MSG_BYTES];
            byte[] temp = new byte[params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES];

            // Generate ephemeralsk <- G(m||pk) mod oA
            byte[] tmp = new byte[params.MSG_BYTES];
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
                ct[i + params.CRYPTO_PUBLICKEYBYTES] = (byte) (temp[i] ^ h[i]);
            }

            // Generate shared secret ss <- H(m||ct)
            System.arraycopy(ct, 0, temp, params.MSG_BYTES, params.CRYPTO_CIPHERTEXTBYTES);

            digest.update(temp, 0, params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES);
            digest.doFinal(ss, 0, params.CRYPTO_BYTES);

            return 0;
        }
    }

    // SIKE's decapsulation
    // Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
    // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    public int crypto_kem_dec(byte[] ss, byte[] ct, byte[] sk)
    {
        if (isCompressed)
        {
            byte[] ephemeralsk_ = new byte[params.SECRETKEY_B_BYTES];
            byte[] jinvariant_ = new byte[params.FP2_ENCODED_BYTES + 2*params.FP2_ENCODED_BYTES + params.SECRETKEY_A_BYTES],
                   h_ = new byte[params.MSG_BYTES];
            byte[] temp = new byte[params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES];
            byte[] tphiBKA_t = jinvariant_;//jinvariant_[params.FP2_ENCODED_BYTES];

            // Decrypt
            sidhCompressed.EphemeralSecretAgreement_A_extended(sk, params.MSG_BYTES, ct, jinvariant_, 1);

            Xof digest = new SHAKEDigest(256);
            digest.update(jinvariant_, 0, params.FP2_ENCODED_BYTES);
            digest.doFinal(h_, 0, params.MSG_BYTES);

            for (int i = 0; i < params.MSG_BYTES; i++)
            {
                temp[i] = (byte) (ct[i + params.PARTIALLY_COMPRESSED_CHUNK_CT] ^ h_[i]);
            }

            // Generate ephemeralsk_ <- G(m||pk) mod oB
            System.arraycopy(sk, params.MSG_BYTES + params.SECRETKEY_A_BYTES, temp, params.MSG_BYTES, params.CRYPTO_PUBLICKEYBYTES);

            digest.update(temp, 0, params.CRYPTO_PUBLICKEYBYTES + params.MSG_BYTES);
            digest.doFinal(ephemeralsk_, 0, params.SECRETKEY_B_BYTES);
            sidhCompressed.FormatPrivKey_B(ephemeralsk_);

            // Generate shared secret ss <- H(m||ct), or output ss <- H(s||ct) in case of ct verification failure
            // No need to recompress, just check if x(phi(P) + t*phi(Q)) == x((a0 + t*a1)*R1 + (b0 + t*b1)*R2)
            byte selector = sidhCompressed.validate_ciphertext(ephemeralsk_, ct, sk, params.MSG_BYTES + params.SECRETKEY_A_BYTES + params.CRYPTO_PUBLICKEYBYTES, tphiBKA_t, params.FP2_ENCODED_BYTES);
            // If ct validation passes (selector = 0) then do ss = H(m||ct), otherwise (selector = -1) load s to do ss = H(s||ct)
            fpx.ct_cmov(temp, sk, params.MSG_BYTES, selector);

            System.arraycopy(ct, 0, temp, params.MSG_BYTES, params.CRYPTO_CIPHERTEXTBYTES);
            digest.update(temp, 0, params.CRYPTO_CIPHERTEXTBYTES + params.MSG_BYTES);
            digest.doFinal(ss, 0, params.CRYPTO_BYTES);

            return 0;
        }
        else
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
                temp[i] = (byte) (ct[i + params.CRYPTO_PUBLICKEYBYTES] ^ h_[i]);
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
}
