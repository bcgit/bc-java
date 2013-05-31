package org.bouncycastle.crypto.prng.drbg;

import java.math.BigInteger;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * A SP800-90A Dual EC DRBG.
 */
public class DualECSP800DRBG
    implements SP80090DRBG
{
    /*
     * Default P, Q values for each curve
     */
    private static final BigInteger p256_Px = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    private static final BigInteger p256_Py = new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    private static final BigInteger p256_Qx = new BigInteger("c97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192", 16);
    private static final BigInteger p256_Qy = new BigInteger("b28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046", 16);

    private static final BigInteger p384_Px = new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16);
    private static final BigInteger p384_Py = new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16);
    private static final BigInteger p384_Qx = new BigInteger("8e722de3125bddb05580164bfe20b8b432216a62926c57502ceede31c47816edd1e89769124179d0b695106428815065", 16);
    private static final BigInteger p384_Qy = new BigInteger("023b1660dd701d0839fd45eec36f9ee7b32e13b315dc02610aa1b636e346df671f790f84c5e09b05674dbb7e45c803dd", 16);

    private static final BigInteger p521_Px = new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16);
    private static final BigInteger p521_Py = new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16);
    private static final BigInteger p521_Qx = new BigInteger("1b9fa3e518d683c6b65763694ac8efbaec6fab44f2276171a42726507dd08add4c3b3f4c1ebc5b1222ddba077f722943b24c3edfa0f85fe24d0c8c01591f0be6f63", 16);
    private static final BigInteger p521_Qy = new BigInteger("1f3bdba585295d9a1110d1df1f9430ef8442c5018976ff3437ef91b81dc0b8132c8d5c39c32d0e004a3092b7d327c0e7a4d26d2c7b69b58f9066652911e457779de", 16);

    private static final long       RESEED_MAX = 1L << (32 - 1);
    private static final int        MAX_ADDITIONAL_INPUT = 1 << (13 - 1);
    private static final int        MAX_ENTROPY_LENGTH = 1 << (13 - 1);
    private static final int        MAX_PERSONALIZATION_STRING = 1 << (13 -1);

    private Digest                 _digest;
    private long                   _reseedCounter;
    private EntropySource          _entropySource;
    private int                    _securityStrength;
    private int                    _seedlen;
    private int                    _outlen;
    private ECCurve.Fp             _curve;
    private ECPoint                _P;
    private ECPoint                _Q;
    private byte[]                 _s;
    private int                    _sLength;

    /**
     * Construct a SP800-90A Dual EC DRBG.
     * <p>
     * Minimum entropy requirement is the security strength requested.
     * </p>
     * @param digest source digest to use with the DRB stream.
     * @param securityStrength security strength required (in bits)
     * @param entropySource source of entropy to use for seeding/reseeding.
     * @param personalizationString personalization string to distinguish this DRBG (may be null).
     * @param nonce nonce to further distinguish this DRBG (may be null).
     */
    public DualECSP800DRBG(Digest digest, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce)
    {
        _digest = digest;
        _entropySource = entropySource;
        _securityStrength = securityStrength;

        if (Utils.isTooLarge(personalizationString, MAX_PERSONALIZATION_STRING / 8))
        {
            throw new IllegalArgumentException("Personalization string too large");
        }

        if (entropySource.entropySize() < securityStrength || entropySource.entropySize() > MAX_ENTROPY_LENGTH)
        {
            throw new IllegalArgumentException("EntropySource must provide between " + securityStrength + " and " + MAX_ENTROPY_LENGTH + " bits");
        }

        byte[] entropy = entropySource.getEntropy();
        byte[] seedMaterial = Arrays.concatenate(entropy, nonce, personalizationString);

        if (securityStrength <= 128)
        {
            if (Utils.getMaxSecurityStrength(digest) < 128)
            {
                throw new IllegalArgumentException("Requested security strength is not supported by digest");
            }
            _seedlen = 256;
            _outlen = 240 / 8;
            _curve = (ECCurve.Fp)NISTNamedCurves.getByName("P-256").getCurve();
            _P = new ECPoint.Fp(_curve, new ECFieldElement.Fp(_curve.getQ(), p256_Px), new ECFieldElement.Fp(_curve.getQ(), p256_Py));
            _Q = new ECPoint.Fp(_curve, new ECFieldElement.Fp(_curve.getQ(), p256_Qx), new ECFieldElement.Fp(_curve.getQ(), p256_Qy));
        }
        else if (securityStrength <= 192)
        {
            if (Utils.getMaxSecurityStrength(digest) < 192)
            {
                throw new IllegalArgumentException("Requested security strength is not supported by digest");
            }
            _seedlen = 384;
            _outlen = 368 / 8;
            _curve = (ECCurve.Fp)NISTNamedCurves.getByName("P-384").getCurve();
            _P = new ECPoint.Fp(_curve, new ECFieldElement.Fp(_curve.getQ(), p384_Px), new ECFieldElement.Fp(_curve.getQ(), p384_Py));
            _Q = new ECPoint.Fp(_curve, new ECFieldElement.Fp(_curve.getQ(), p384_Qx), new ECFieldElement.Fp(_curve.getQ(), p384_Qy));
        }
        else if (securityStrength <= 256)
        {
            if (Utils.getMaxSecurityStrength(digest) < 256)
            {
                throw new IllegalArgumentException("Requested security strength is not supported by digest");
            }
            _seedlen = 521;
            _outlen = 504 / 8;
            _curve = (ECCurve.Fp)NISTNamedCurves.getByName("P-521").getCurve();
            _P = new ECPoint.Fp(_curve, new ECFieldElement.Fp(_curve.getQ(), p521_Px), new ECFieldElement.Fp(_curve.getQ(), p521_Py));
            _Q = new ECPoint.Fp(_curve, new ECFieldElement.Fp(_curve.getQ(), p521_Qx), new ECFieldElement.Fp(_curve.getQ(), p521_Qy));
        }
        else
        {
            throw new IllegalArgumentException("security strength cannot be greater than 256 bits");
        }

        _s = Utils.hash_df(_digest, seedMaterial, _seedlen);
        _sLength = _s.length;

        _reseedCounter = 0;
    }

    /**
     * Populate a passed in array with random data.
     *
     * @param output output array for generated bits.
     * @param additionalInput additional input to be added to the DRBG in this step.
     * @param predictionResistant true if a reseed should be forced, false otherwise.
     *
     * @return number of bits generated, -1 if a reseed required.
     */
    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        int numberOfBits = output.length*8;
        int m = output.length / _outlen;

        if (Utils.isTooLarge(additionalInput, MAX_ADDITIONAL_INPUT / 8))
        {
            throw new IllegalArgumentException("Additional input too large");
        }

        if (_reseedCounter + m > RESEED_MAX)
        {
            return -1;
        }

        if (predictionResistant)
        {   
            reseed(additionalInput);
            additionalInput = null;
        }

        if (additionalInput != null)
        {
            // Note: we ignore the use of pad8 on the additional input as we mandate byte arrays for it.
            additionalInput = Utils.hash_df(_digest, additionalInput, _seedlen);
        }

        for (int i = 0; i < m; i++)
        {
            BigInteger t = new BigInteger(1, xor(_s, additionalInput));

            _s = _P.multiply(t).getX().toBigInteger().toByteArray();

            //System.err.println("S: " + new String(Hex.encode(_s)));

            byte[] r = _Q.multiply(new BigInteger(1, _s)).getX().toBigInteger().toByteArray();

            if (r.length > _outlen)
            {
                System.arraycopy(r, r.length - _outlen, output, i * _outlen, _outlen);
            }
            else
            {
                System.arraycopy(r, 0, output, i * _outlen + (_outlen - r.length), r.length);
            }

            //System.err.println("R: " + new String(Hex.encode(r)));
            additionalInput = null;

            _reseedCounter++;
        }

        if (m * _outlen < output.length)
        {
            BigInteger t = new BigInteger(1, xor(_s, additionalInput));

            _s = _P.multiply(t).getX().toBigInteger().toByteArray();

            byte[] r = _Q.multiply(new BigInteger(1, _s)).getX().toBigInteger().toByteArray();

            System.arraycopy(r, 0, output, m * _outlen, output.length - (m * _outlen));
        }

        // Need to preserve length of S as unsigned int.
        _s = BigIntegers.asUnsignedByteArray(_sLength, _P.multiply(new BigInteger(1, _s)).getX().toBigInteger());

        return numberOfBits;
    }

    /**
      * Reseed the DRBG.
      *
      * @param additionalInput additional input to be added to the DRBG in this step.
      */
    public void reseed(byte[] additionalInput)
    {
        if (Utils.isTooLarge(additionalInput, MAX_ADDITIONAL_INPUT / 8))
        {
            throw new IllegalArgumentException("Additional input string too large");
        }

        byte[] entropy = _entropySource.getEntropy();
        byte[] seedMaterial = Arrays.concatenate(pad8(_s, _seedlen), entropy, additionalInput);

        _s = Utils.hash_df(_digest, seedMaterial, _seedlen);

        _reseedCounter = 0;
    }

    private byte[] xor(byte[] a, byte[] b)
    {
        if (b == null)
        {
            return a;
        }

        byte[] rv = new byte[a.length];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = (byte)(a[i] ^ b[i]);
        }

        return rv;
    }

    // Note: works in place
    private byte[] pad8(byte[] s, int seedlen)
    {
        if (seedlen % 8 == 0)
        {
            return s;
        }

        int shift = 8 - (seedlen % 8);
        int carry = 0;

        for (int i = s.length - 1; i >= 0; i--)
        {
            int b = s[i] & 0xff;
            s[i] = (byte)((b << shift) | (carry >> (8 - shift)));
            carry = b;
        }

        return s;
    }
}
