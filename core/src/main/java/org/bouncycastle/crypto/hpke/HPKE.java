package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class HPKE
{

    //modes
    private static final byte mode_base = 0x00;
    private static final byte mode_psk = 0x01;
    private static final byte mode_auth = 0x02;
    private static final byte mode_auth_psk = 0x03;


    private final byte[] default_psk = null;
    private final byte[] default_psk_id = null;

    private final byte mode;
    private final short kemId;
    private final short kdfId;
    private final short aeadId;


    public final DHKEM dhkem;
    public final HKDF hkdf;
    public AEAD aead;


    short Nk;

    /**
     * Hybrid Public Key Encryption as described in RFC9180.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html">
     * RFC9180 An implementation of the Hybrid Public Key Encryption.</a>
     */
    public HPKE(byte mode, short kemId, short kdfId, short aeadId)
            throws Exception
    {
        this.mode = mode;
        this.kemId = kemId;
        this.kdfId = kdfId;
        this.aeadId = aeadId;
        this.hkdf = new HKDF(kdfId);
        this.dhkem = new DHKEM(kemId);
        if (aeadId == AEAD.AEAD_AESGCM128)
        {
            Nk = 16;
        }
        else
        {
            Nk = 32;
        }
    }

    // initializer for the aead
    public void AEAD(byte[] key, byte[] nonce)
    {
        this.aead = new AEAD(key, nonce, aeadId);
    }

    private void VerifyPSKInputs(byte mode, byte[] psk, byte[] pskid)
            throws Exception
    {
        boolean got_psk = (!Arrays.areEqual(psk, default_psk));
        boolean got_psk_id = (!Arrays.areEqual(pskid, default_psk_id));
        if (got_psk != got_psk_id)
            throw new Exception("Inconsistent PSK inputs");

        if (got_psk && (mode % 2 == 0))
        {
            throw new Exception("PSK input provided when not needed");
        }
        if ((!got_psk) && (mode % 2 == 1))
        {
            throw new Exception("Missing required PSK input");
        }
    }

    private Context KeySchedule(byte mode, byte[] sharedSecret, byte[] info, byte[] psk, byte[] pskid)
            throws Exception
    {
        ////System.out.println("\nKeySchedule");

        VerifyPSKInputs(mode, psk, pskid);
        byte[] suiteId = Arrays.concatenate(
                "HPKE".getBytes(),
                Pack.shortToBigEndian(kemId),
                Pack.shortToBigEndian(kdfId),
                Pack.shortToBigEndian(aeadId));

        ////System.out.println("suiteId" + ": " + Hex.toHexString(suiteId));
        byte[] pskidHash = hkdf.LabeledExtract(null, suiteId,"psk_id_hash", pskid);
        ////System.out.println("pskidHash" + ": " + Hex.toHexString(pskidHash));

        byte[] infoHash = hkdf.LabeledExtract(null, suiteId, "info_hash", info);
        ////System.out.println("infoHash" + ": " + Hex.toHexString(infoHash));

        byte[] modeArray = new byte[1];
        modeArray[0] = mode;
        byte[] keyScheduleContext = Arrays.concatenate(modeArray, pskidHash, infoHash);
        ////System.out.println("keyScheduleContext" + ": " + Hex.toHexString(keyScheduleContext));

        byte[] secret = hkdf.LabeledExtract(sharedSecret, suiteId, "secret", psk);

        byte[] key = hkdf.LabeledExpand(secret, suiteId, "key", keyScheduleContext, Nk);
        byte[] base_nonce = hkdf.LabeledExpand(secret, suiteId, "base_nonce", keyScheduleContext, 12);//Nn
        byte[] exporter_secret = hkdf.LabeledExpand(secret, suiteId, "exp", keyScheduleContext, hkdf.getHashSize());//todo Nk*2 with replace hash digest size
        ////System.out.println("exporter_secret" + ": " + Hex.toHexString(exporter_secret));
        ////System.out.println("L:" + hkdf.getHashSize());

        aead = new AEAD(key, base_nonce, aeadId);
        return new Context(aead, hkdf, exporter_secret, suiteId);
    }

    public byte[][] SendExport(AsymmetricKeyParameter pkR, byte[] info, byte[] exporterContext, int L,
                    byte[] psk, byte[] pskId, AsymmetricCipherKeyPair skS)
        throws Exception
    {
        Context ctx;
        byte[][] output = new byte[2][]; // ct and enc
        switch (mode)
        {
            case mode_base:
                ctx = SetupBaseS(pkR, info);
                break;
            case mode_auth:
                ctx = SetupAuthS(pkR, info, skS);
                break;
            case mode_psk:
                ctx = SetupPSKS(pkR, info, psk, pskId);
                break;
            case mode_auth_psk:
                ctx = SetupAuthPSKS(pkR, info, psk, pskId, skS);
                break;
            default:
                throw new Exception("Unknown mode");
        }
        output[0] = ctx.enc;
        output[1] = ctx.Export(exporterContext, L);
        return output;
    }

    public byte[] ReceiveExport(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] exporterContext, int L,
                byte[] psk, byte[] pskId, AsymmetricKeyParameter pkS)
            throws Exception
    {
        Context ctx;
        switch (mode)
        {
            case mode_base:
                ctx = SetupBaseR(enc, skR, info);
                break;
            case mode_auth:
                ctx = SetupAuthR(enc, skR, info, pkS);
                break;
            case mode_psk:
                ctx = SetupPSKR(enc, skR, info, psk, pskId);
                break;
            case mode_auth_psk:
                ctx = SetupAuthPSKR(enc, skR, info, psk, pskId, pkS);
                break;
            default:
                throw new Exception("Unknown mode");
        }
        return ctx.Export(exporterContext, L);
    }

    public byte[][] Seal(AsymmetricKeyParameter pkR, byte[] info, byte[] aad, byte[] pt,
                  byte[] psk, byte[] pskId, AsymmetricCipherKeyPair skS)
        throws Exception
    {
        Context ctx;
        byte[][] output = new byte[2][]; // ct and enc
        switch (mode)
        {
            case mode_base:
                ctx = SetupBaseS(pkR, info);
                break;
            case mode_auth:
                ctx = SetupAuthS(pkR, info, skS);
                break;
            case mode_psk:
                ctx = SetupPSKS(pkR, info, psk, pskId);
                break;
            case mode_auth_psk:
                ctx = SetupAuthPSKS(pkR, info, psk, pskId, skS);
                break;
            default:
                throw new Exception("Unknown mode");
        }
        output[0] = ctx.aead.Seal(aad, pt);
        output[1] = ctx.enc;
        return output;
    }

    public byte[] Open(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] aad, byte[] ct,
                  byte[] psk, byte[] pskId, AsymmetricKeyParameter pkS)
        throws Exception
    {
        Context ctx;
        switch (mode)
        {
            case mode_base:
                ctx = SetupBaseR(enc, skR, info);
                break;
            case mode_auth:
                ctx = SetupAuthR(enc, skR, info, pkS);
                break;
            case mode_psk:
                ctx = SetupPSKR(enc, skR, info, psk, pskId);
                break;
            case mode_auth_psk:
                ctx = SetupAuthPSKR(enc, skR, info, psk, pskId, pkS);
                break;
            default:
                throw new Exception("Unknown mode");
        }
        return ctx.aead.Open(aad, ct);
    }


    public Context SetupBaseS(AsymmetricKeyParameter pkR, byte[] info)
        throws Exception
    {
        byte[][] output = dhkem.Encap(pkR); // sharedSecret, enc
        Context ctx = KeySchedule(mode_base, output[0], info, default_psk, default_psk_id);
        ctx.SetEnc(output[1]);
        return ctx;
    }

    public Context SetupBaseR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info)
        throws Exception
    {
        byte[] sharedSecret = dhkem.Decap(enc, skR);
//        System.out.println("sharedSecret: " + Hex.toHexString(sharedSecret));
        return KeySchedule(mode_base, sharedSecret, info, default_psk, default_psk_id);
    }

    public Context SetupPSKS(AsymmetricKeyParameter pkR, byte[] info, byte[] psk, byte[] psk_id)
        throws Exception
    {
        byte[][] output = dhkem.Encap(pkR); // sharedSecret, enc

        Context ctx = KeySchedule(mode_psk, output[0], info, psk, psk_id);
        ctx.SetEnc(output[1]);
        return ctx;
    }

    public Context SetupPSKR (byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] psk, byte[] psk_id)
        throws Exception
    {
        byte[] sharedSecret = dhkem.Decap(enc, skR);
        return KeySchedule(mode_psk, sharedSecret, info, psk, psk_id);
    }

    public Context SetupAuthS(AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair skS)
        throws Exception
    {
        byte[][] output = dhkem.AuthEncap(pkR, skS);
        Context ctx = KeySchedule(mode_auth, output[0], info, default_psk, default_psk_id);
        ctx.SetEnc(output[1]);
        return ctx;
    }

    public Context SetupAuthR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, AsymmetricKeyParameter pkS)
            throws Exception
    {
        byte[] sharedSecret = dhkem.AuthDecap(enc, skR, pkS);
        return KeySchedule(mode_auth, sharedSecret, info, default_psk, default_psk_id);
    }

    public Context SetupAuthPSKS(AsymmetricKeyParameter pkR, byte[] info, byte[] psk, byte[] psk_id, AsymmetricCipherKeyPair skS)
            throws Exception
    {
        byte[][] output = dhkem.AuthEncap(pkR, skS);
        Context ctx = KeySchedule(mode_auth_psk, output[0], info, psk, psk_id);
        ctx.SetEnc(output[1]);
        return ctx;
    }

    public Context SetupAuthPSKR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] psk, byte[] psk_id, AsymmetricKeyParameter pkS)
        throws Exception
    {
        byte[] sharedSecret = dhkem.AuthDecap(enc, skR, pkS);
        return KeySchedule(mode_auth_psk, sharedSecret, info, psk, psk_id);
    }




}
