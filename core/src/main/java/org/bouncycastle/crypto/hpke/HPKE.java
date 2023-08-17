package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

public class HPKE
{
    // modes
    public static final byte mode_base = 0x00;
    public static final byte mode_psk = 0x01;
    public static final byte mode_auth = 0x02;
    public static final byte mode_auth_psk = 0x03;

    // kems
    public static final short kem_P256_SHA256 = 16;
    public static final short kem_P384_SHA348 = 17;
    public static final short kem_P521_SHA512 = 18;
    public static final short kem_X25519_SHA256 = 32;
    public static final short kem_X448_SHA512 = 33;

    // kdfs
    public static final short kdf_HKDF_SHA256 = 0x0001;
    public static final short kdf_HKDF_SHA384 = 0x0002;
    public static final short kdf_HKDF_SHA512 = 0x0003;

    // aeads
    public static final short aead_AES_GCM128 = 0x0001;
    public static final short aead_AES_GCM256 = 0x0002;
    public static final short aead_CHACHA20_POLY1305 = 0x0003;
    public static final short aead_EXPORT_ONLY = (short) 0xFFFF;

    private final byte[] default_psk = null;
    private final byte[] default_psk_id = null;

    private final byte mode;
    private final short kemId;
    private final short kdfId;
    private final short aeadId;
    private final DHKEM dhkem;
    private final HKDF hkdf;

    short Nk;

    /**
     * Hybrid Public Key Encryption as described in RFC9180.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html">
     * RFC9180 An implementation of the Hybrid Public Key Encryption.</a>
     */
    public HPKE(byte mode, short kemId, short kdfId, short aeadId)
    {
        this.mode = mode;
        this.kemId = kemId;
        this.kdfId = kdfId;
        this.aeadId = aeadId;
        this.hkdf = new HKDF(kdfId);
        this.dhkem = new DHKEM(kemId);
        if (aeadId == aead_AES_GCM128)
        {
            Nk = 16;
        }
        else
        {
            Nk = 32;
        }
    }

    private void VerifyPSKInputs(byte mode, byte[] psk, byte[] pskid)
    {
        boolean got_psk = (!Arrays.areEqual(psk, default_psk));
        boolean got_psk_id = (!Arrays.areEqual(pskid, default_psk_id));
        if (got_psk != got_psk_id)
        {
            throw new IllegalArgumentException("Inconsistent PSK inputs");
        }

        if (got_psk && (mode % 2 == 0))
        {
            throw new IllegalArgumentException("PSK input provided when not needed");
        }
        if ((!got_psk) && (mode % 2 == 1))
        {
            throw new IllegalArgumentException("Missing required PSK input");
        }
    }

    private HPKEContext keySchedule(byte mode, byte[] sharedSecret, byte[] info, byte[] psk, byte[] pskid)
    {
        VerifyPSKInputs(mode, psk, pskid);
        byte[] suiteId = Arrays.concatenate(
            Strings.toByteArray("HPKE"),
            Pack.shortToBigEndian(kemId),
            Pack.shortToBigEndian(kdfId),
            Pack.shortToBigEndian(aeadId));

        byte[] pskidHash = hkdf.LabeledExtract(null, suiteId, "psk_id_hash", pskid);

        byte[] infoHash = hkdf.LabeledExtract(null, suiteId, "info_hash", info);

        byte[] modeArray = new byte[1];
        modeArray[0] = mode;
        byte[] keyScheduleContext = Arrays.concatenate(modeArray, pskidHash, infoHash);

        byte[] secret = hkdf.LabeledExtract(sharedSecret, suiteId, "secret", psk);

        byte[] key = hkdf.LabeledExpand(secret, suiteId, "key", keyScheduleContext, Nk);
        byte[] base_nonce = hkdf.LabeledExpand(secret, suiteId, "base_nonce", keyScheduleContext, 12);//Nn
        byte[] exporter_secret = hkdf.LabeledExpand(secret, suiteId, "exp", keyScheduleContext, hkdf.getHashSize());//todo Nk*2 with replace hash digest size

        return new HPKEContext(new AEAD(aeadId, key, base_nonce), hkdf, exporter_secret, suiteId);
    }

    public AsymmetricCipherKeyPair generatePrivateKey()
    {
        return dhkem.GeneratePrivateKey();
    }


    public byte[] serializePublicKey(AsymmetricKeyParameter pk)
    {
        return dhkem.SerializePublicKey(pk);
    }

    public byte[] serializePrivateKey(AsymmetricKeyParameter sk)
    {
        return dhkem.SerializePrivateKey(sk);
    }
    public AsymmetricKeyParameter deserializePublicKey(byte[] pkEncoded)
    {
        return dhkem.DeserializePublicKey(pkEncoded);
    }

    public AsymmetricCipherKeyPair deserializePrivateKey(byte[] skEncoded, byte[] pkEncoded)
    {
        return dhkem.DeserializePrivateKey(skEncoded, pkEncoded);
    }

    public AsymmetricCipherKeyPair deriveKeyPair(byte[] ikm)
    {
        return dhkem.DeriveKeyPair(ikm);
    }

    public byte[][] sendExport(AsymmetricKeyParameter pkR, byte[] info, byte[] exporterContext, int L,
                               byte[] psk, byte[] pskId, AsymmetricCipherKeyPair skS)
    {
        HPKEContextWithEncapsulation ctx;
        byte[][] output = new byte[2][]; // ct and enc
        switch (mode)
        {
        case mode_base:
            ctx = setupBaseS(pkR, info);
            break;
        case mode_auth:
            ctx = setupAuthS(pkR, info, skS);
            break;
        case mode_psk:
            ctx = SetupPSKS(pkR, info, psk, pskId);
            break;
        case mode_auth_psk:
            ctx = setupAuthPSKS(pkR, info, psk, pskId, skS);
            break;
        default:
            throw new IllegalStateException("Unknown mode");
        }
        output[0] = ctx.encapsulation;
        output[1] = ctx.export(exporterContext, L);
        return output;
    }

    public byte[] receiveExport(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] exporterContext, int L,
                                byte[] psk, byte[] pskId, AsymmetricKeyParameter pkS)
    {
        HPKEContext ctx;
        switch (mode)
        {
        case mode_base:
            ctx = setupBaseR(enc, skR, info);
            break;
        case mode_auth:
            ctx = setupAuthR(enc, skR, info, pkS);
            break;
        case mode_psk:
            ctx = setupPSKR(enc, skR, info, psk, pskId);
            break;
        case mode_auth_psk:
            ctx = setupAuthPSKR(enc, skR, info, psk, pskId, pkS);
            break;
        default:
            throw new IllegalStateException("Unknown mode");
        }
        return ctx.export(exporterContext, L);
    }

    public byte[][] seal(AsymmetricKeyParameter pkR, byte[] info, byte[] aad, byte[] pt,
                         byte[] psk, byte[] pskId, AsymmetricCipherKeyPair skS)
        throws InvalidCipherTextException
    {
        HPKEContextWithEncapsulation ctx;
        byte[][] output = new byte[2][]; // ct and enc
        switch (mode)
        {
        case mode_base:
            ctx = setupBaseS(pkR, info);
            break;
        case mode_auth:
            ctx = setupAuthS(pkR, info, skS);
            break;
        case mode_psk:
            ctx = SetupPSKS(pkR, info, psk, pskId);
            break;
        case mode_auth_psk:
            ctx = setupAuthPSKS(pkR, info, psk, pskId, skS);
            break;
        default:
            throw new IllegalStateException("Unknown mode");
        }
        output[0] = ctx.seal(aad, pt);
        output[1] = ctx.getEncapsulation();
        return output;
    }

    public byte[] open(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] aad, byte[] ct,
                       byte[] psk, byte[] pskId, AsymmetricKeyParameter pkS)
        throws InvalidCipherTextException
    {
        HPKEContext ctx;
        switch (mode)
        {
        case mode_base:
            ctx = setupBaseR(enc, skR, info);
            break;
        case mode_auth:
            ctx = setupAuthR(enc, skR, info, pkS);
            break;
        case mode_psk:
            ctx = setupPSKR(enc, skR, info, psk, pskId);
            break;
        case mode_auth_psk:
            ctx = setupAuthPSKR(enc, skR, info, psk, pskId, pkS);
            break;
        default:
            throw new IllegalStateException("Unknown mode");
        }
        return ctx.open(aad, ct);
    }

    public HPKEContextWithEncapsulation setupBaseS(AsymmetricKeyParameter pkR, byte[] info)
    {
        byte[][] output = dhkem.Encap(pkR); // sharedSecret, enc
        HPKEContext ctx = keySchedule(mode_base, output[0], info, default_psk, default_psk_id);

        return new HPKEContextWithEncapsulation(ctx, output[1]);
    }

    // Variant of setupBaseS() where caller can provide their own ephemeral key pair.
    // This should only be used to validate test vectors.
    public HPKEContextWithEncapsulation setupBaseS(AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair kpE)
    {
        byte[][] output = dhkem.Encap(pkR, kpE); // sharedSecret, enc
        HPKEContext ctx = keySchedule(mode_base, output[0], info, default_psk, default_psk_id);

        return new HPKEContextWithEncapsulation(ctx, output[1]);
    }

    public HPKEContext setupBaseR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info)
    {
        byte[] sharedSecret = dhkem.Decap(enc, skR);
        return keySchedule(mode_base, sharedSecret, info, default_psk, default_psk_id);
    }

    public HPKEContextWithEncapsulation SetupPSKS(AsymmetricKeyParameter pkR, byte[] info, byte[] psk, byte[] psk_id)
    {
        byte[][] output = dhkem.Encap(pkR); // sharedSecret, enc

        HPKEContext ctx = keySchedule(mode_psk, output[0], info, psk, psk_id);

        return new HPKEContextWithEncapsulation(ctx, output[1]);
    }

    public HPKEContext setupPSKR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] psk, byte[] psk_id)
    {
        byte[] sharedSecret = dhkem.Decap(enc, skR);
        return keySchedule(mode_psk, sharedSecret, info, psk, psk_id);
    }

    public HPKEContextWithEncapsulation setupAuthS(AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair skS)
    {
        byte[][] output = dhkem.AuthEncap(pkR, skS);
        HPKEContext ctx = keySchedule(mode_auth, output[0], info, default_psk, default_psk_id);

        return new HPKEContextWithEncapsulation(ctx, output[1]);
    }

    public HPKEContext setupAuthR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, AsymmetricKeyParameter pkS)
    {
        byte[] sharedSecret = dhkem.AuthDecap(enc, skR, pkS);
        return keySchedule(mode_auth, sharedSecret, info, default_psk, default_psk_id);
    }

    public HPKEContextWithEncapsulation setupAuthPSKS(AsymmetricKeyParameter pkR, byte[] info, byte[] psk, byte[] psk_id, AsymmetricCipherKeyPair skS)
    {
        byte[][] output = dhkem.AuthEncap(pkR, skS);
        HPKEContext ctx = keySchedule(mode_auth_psk, output[0], info, psk, psk_id);

        return new HPKEContextWithEncapsulation(ctx, output[1]);
    }

    public HPKEContext setupAuthPSKR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] psk, byte[] psk_id, AsymmetricKeyParameter pkS)
    {
        byte[] sharedSecret = dhkem.AuthDecap(enc, skR, pkS);
        return keySchedule(mode_auth_psk, sharedSecret, info, psk, psk_id);
    }
}
