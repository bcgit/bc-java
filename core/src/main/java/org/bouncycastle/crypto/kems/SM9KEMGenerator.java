package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.crypto.digests.SM9Sm3;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * SM9 key encapsulation mechanism - encapsulation side (GM/T 0044.4-2016, clause 6).
 * Given a recipient identity and the encryption master public key, produces a
 * shared key K and its encapsulation C = [r]Q_B (a G1 point, encoded x||y).
 */
public class SM9KEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final int keyLenBits;
    private final SecureRandom random;

    public SM9KEMGenerator(int keyLenBits, SecureRandom random)
    {
        this.keyLenBits = keyLenBits;
        this.random = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        SM9EncPublicKeyParameters rk = (SM9EncPublicKeyParameters)recipientKey;
        SM9EncMasterPublicKeyParameters master = rk.getMasterPublicKey();
        byte[] id = rk.getIdentity();

        ECPoint qb = master.recipientPoint(id);
        Fp12 g = master.pairingWithP2();
        SecureRandom rand = CryptoServicesRegistrar.getSecureRandom(random);
        BigInteger n = SM9Curve.N;

        byte[] key;
        byte[] encap;
        do
        {
            BigInteger r = BigIntegers.createRandomInRange(ECConstants.ONE, n.subtract(ECConstants.ONE), rand);
            ECPoint c = SM9Curve.multiplySecure(qb, r).normalize();   // C = [r]Q_B
            Fp12 w = g.powSecure(r);
            encap = SM9Curve.g1ToBytes(c);
            key = SM9Sm3.kdf(Arrays.concatenate(encap, SM9Pairing.toBytes(w), id), keyLenBits);
        }
        while (Arrays.areAllZeroes(key, 0, key.length));

        return new SecretWithEncapsulationImpl(key, encap);
    }
}
