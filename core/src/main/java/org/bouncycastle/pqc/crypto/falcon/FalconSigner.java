package org.bouncycastle.pqc.crypto.falcon;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

public class FalconSigner
    implements MessageSigner
{

    private byte[] keydata;
    private int logn;

    private int nounce_len;

    private SecureRandom random;

    private static final int noncelen = 40;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                this.keydata = ((FalconPrivateKeyParameters)((ParametersWithRandom)param).getParameters()).getPrivateKey();
                this.random = ((ParametersWithRandom)param).getRandom();
            }
            else
            {
                this.keydata = ((FalconPrivateKeyParameters)param).getPrivateKey();
                this.random = new SecureRandom();
            }
        }
        else
        {
            this.keydata = ((FalconPublicKeyParameters)param).getPublicKey();
        }
        this.logn = ((FalconKeyParameters)param).getParam().getLogn();
        this.nounce_len = ((FalconKeyParameters)param).getParam().getNounceLen();
    }

    //TODO generate signature - see crypto_sign in nist.c
    public byte[] generateSignature(byte[] message)
    {

        return new byte[0];
    }

    //TODO verify signature - see crypto_sign_open in nist.c
    //TODO ask about nounce
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        byte[] pk = Arrays.clone(this.keydata);
        int n = 1 << this.logn;
        int pk_bytes = ((n * 14) + 8) >> 3;
        short[] h = new short[n];
        // decode pk
        if (pk[0] != 0x00 + this.logn)
        {
            return false;
        }
        if (FalconCommon.modq_decode(0, h, logn, 1, pk, pk_bytes - 1) != pk_bytes - 1)
        {
            return false;
        }
        FalconNTT h_nttm = FalconNTT.to_ntt_monty(new FalconShortPoly(h), this.logn);
        // find nonce, signature (attach nounce to start of sig?)
        byte[] nonce = new byte[noncelen];
        int esig = noncelen;
        int siglen = (signature.length - noncelen);
        short[] sig = new short[n];
        System.arraycopy(signature, 0, nonce, 0, noncelen);
        // decode signature
        if (signature.length - noncelen < 1 || signature[esig] != 0x20 + 10)
        {
            return false;
        }
        if (FalconCommon.comp_decode(0, sig, this.logn, esig + 1, signature, siglen - 1) != siglen - 1)
        {
            return false;
        }
        // hash nonce+message into a vector
        short[] hm = new short[n];
        FalconSHAKE256 sc = new FalconSHAKE256();
        sc.inject(nonce, noncelen);
        sc.inject(message, message.length);
        sc.flip();
        FalconCommon.hash_to_point_ct(sc, 0, hm, this.logn);
        // verify_raw
        return verify_raw(hm, sig, h_nttm, this.logn);
    }

    /**
     * signature verification
     *
     * @param c0   hashed nonce+message
     * @param s2   decoded sig
     * @param h    pk in NTT + monty format
     * @param logn
     * @return true if passes, false if fails
     */
    private static boolean verify_raw(short[] c0, short[] s2, FalconNTT h, int logn)
    {
        int Q = 12289;
        int u, n;
        short[] tt;
        n = 1 << logn;
        tt = new short[n];
        /*
         * Reduce s2 elements modulo q ([0..q-1] range).
         */
        for (u = 0; u < n; u++)
        {
            int w;

            w = (int)s2[u]; // s2 is signed so direct upcasting is fine
            w += Q & -(w >> 31);
            tt[u] = (short)w;
        }

        /*
         * Compute -s1 = s2*h - c0 mod phi mod q (in tt[]).
         */
        FalconNTT tt_ntt = new FalconNTT(tt, logn);
        tt_ntt.mq_poly_montymul_ntt(h, logn);
        tt = tt_ntt.mq_iNTT(logn).coeffs;
        FalconNTT.mq_poly_sub(tt, c0, logn);

        /*
         * Normalize -s1 elements into the [-q/2..q/2] range.
         */
        for (u = 0; u < n; u++)
        {
            int w;

            w = (int)tt[u];
            w -= (Q & -(((Q >> 1) - w) >>> 31));
            tt[u] = (short)w;
        }

        /*
         * Signature is valid if and only if the aggregate (-s1,s2) vector
         * is short enough.
         */
        return FalconCommon.is_short(tt, s2, logn);
    }
}
