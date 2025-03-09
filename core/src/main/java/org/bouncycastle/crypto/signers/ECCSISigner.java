package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ECCSIPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECCSIPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Implementation of Elliptic Curve-based Certificateless Signatures for Identity-Based Encryption (ECCSI)
 * as defined in RFC 6507.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6507">RFC 6507:  Elliptic Curve-Based Certificateless
 * Signatures for Identity-Based Encryption (ECCSI)</a>
 */
public class ECCSISigner
    implements Signer
{
    private final BigInteger q;
    private final ECPoint G;
    private final Digest digest;
    private BigInteger j;
    private BigInteger r;
    private ECPoint Y;
    private final ECPoint kpak;
    private final byte[] id;
    private CipherParameters param;
    private ByteArrayOutputStream stream;
    private boolean forSigning;
    private final int N;

    /**
     * Constructs an ECCSI signer/verifier with KMS Public Authentication Key and user identity.
     *
     * @param kpak KMS Public Authentication Key (KPAK) from RFC 6507 Section 2
     * @param id   User identity byte array formatted
     */
    public ECCSISigner(ECPoint kpak, X9ECParameters params, Digest digest, byte[] id)
    {
        this.kpak = kpak;
        this.id = id;
        this.q = params.getCurve().getOrder();
        this.G = params.getG();
        this.digest = digest;
        this.digest.reset();
        this.N = (params.getCurve().getOrder().bitLength() + 7) >> 3;
    }

    /**
     * Initializes the signer for either signature generation or verification.
     *
     * @param forSigning true for signing, false for verification
     * @param param      Key parameters:
     *                   - For signing: {@code ParametersWithRandom} containing {@code ECCSIPrivateKeyParameters}
     *                   - For verification: {@code ECCSIPublicKeyParameters}
     * @throws IllegalArgumentException if invalid parameters are provided
     */
    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        this.forSigning = forSigning;
        this.param = param;
        reset();
    }

    @Override
    public void update(byte b)
    {
        if (forSigning)
        {
            digest.update(b);
        }
        else
        {
            stream.write(b);
        }
    }

    @Override
    public void update(byte[] in, int off, int len)
    {
        if (forSigning)
        {
            digest.update(in, off, len);
        }
        else
        {
            stream.write(in, off, len);
        }
    }

    /**
     * Generates an ECCSI signature according to RFC 6507 Section 5.2.1.
     *
     * @return Signature structure containing:
     *         - r (N bytes)
     *         - s (N bytes)
     *         - PVT (Public Validation Token)
     * @throws CryptoException       if cryptographic operations fail
     * @throws DataLengthException   if input data is invalid
     * @throws IllegalArgumentException if invalid SSK or j parameter is detected
     */
    @Override
    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        byte[] heBytes = new byte[digest.getDigestSize()];
        digest.doFinal(heBytes, 0);

        //Compute s' = ( (( HE + r * SSK )^-1) * j ) modulo q
        ECCSIPrivateKeyParameters params = (ECCSIPrivateKeyParameters)(((ParametersWithRandom)param).getParameters());
        BigInteger ssk = params.getSSK();
        BigInteger denominator = new BigInteger(1, heBytes).add(r.multiply(ssk)).mod(q);
        if (denominator.equals(BigInteger.ZERO))
        {
            throw new IllegalArgumentException("Invalid j, retry");
        }

        BigInteger sPrime = denominator.modInverse(q).multiply(j).mod(q);

        return Arrays.concatenate(BigIntegers.asUnsignedByteArray(this.N, r), BigIntegers.asUnsignedByteArray(this.N, sPrime),
            params.getPublicKeyParameters().getPVT().getEncoded(false));
    }

    /**
     * Verifies an ECCSI signature according to RFC 6507 Section 5.2.2.
     *
     * @param signature Signature to verify (r || s || PVT)
     * @return true if signature is valid, false otherwise
     * @throws IllegalArgumentException if signature format is invalid
     */
    @Override
    public boolean verifySignature(byte[] signature)
    {
        byte[] bytes = Arrays.copyOf(signature, this.N);
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, this.N, this.N << 1));
        r = new BigInteger(1, bytes).mod(q);
        digest.update(bytes, 0, this.N);
        bytes = stream.toByteArray();
        digest.update(bytes, 0, bytes.length);
        bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);

        BigInteger HE = new BigInteger(1, bytes).mod(q);

        // Compute J = s*(HE*G + r*Y)
        ECPoint HE_G = G.multiply(HE).normalize();
        ECPoint rY = Y.multiply(r).normalize();
        ECPoint sum = HE_G.add(rY).normalize();
        ECPoint J = sum.multiply(s).normalize();

        BigInteger rComputed = J.getAffineXCoord().toBigInteger();

        return rComputed.mod(q).equals(r.mod(q));
    }

    /**
     * Resets the signer/verifier state and performs initial computations:
     * - For signing: Validates KPAK consistency (RFC 6507 Section 5.1.2)
     * - For verification: Computes Y = HS·PVT + KPAK
     *
     * Also computes HS = hash(G || KPAK || ID || PVT) as per RFC 6507 Section 5.1.1
     */
    @Override
    public void reset()
    {
        digest.reset();
        CipherParameters param = this.param;
        SecureRandom random = null;
        if (param instanceof ParametersWithRandom)
        {
            random = ((ParametersWithRandom)param).getRandom();
            param = ((ParametersWithRandom)param).getParameters();
        }
        ECPoint kpak_computed = null;
        ECPoint pvt;
        if (forSigning)
        {
            ECCSIPrivateKeyParameters parameters = (ECCSIPrivateKeyParameters)param;
            pvt = parameters.getPublicKeyParameters().getPVT();
            j = BigIntegers.createRandomBigInteger(q.bitLength(), random);
            ECPoint J = G.multiply(j).normalize();
            r = J.getAffineXCoord().toBigInteger().mod(q);

            kpak_computed = G.multiply(parameters.getSSK());
        }
        else
        {
            ECCSIPublicKeyParameters parameters = (ECCSIPublicKeyParameters)param;
            pvt = parameters.getPVT();
            stream = new ByteArrayOutputStream();
        }

        // compute HS
        byte[] tmp = G.getEncoded(false);
        digest.update(tmp, 0, tmp.length);
        tmp = kpak.getEncoded(false);
        digest.update(tmp, 0, tmp.length);
        digest.update(id, 0, id.length);
        tmp = pvt.getEncoded(false);
        digest.update(tmp, 0, tmp.length);
        tmp = new byte[digest.getDigestSize()];
        digest.doFinal(tmp, 0);
        BigInteger HS = new BigInteger(1, tmp).mod(q);

        //HE = hash( HS || r || M );
        digest.update(tmp, 0, tmp.length);
        if (forSigning)
        {
            kpak_computed = kpak_computed.subtract(pvt.multiply(HS)).normalize();
            if (!kpak_computed.equals(kpak))
            {
                throw new IllegalArgumentException("Invalid KPAK");
            }
            byte[] rBytes = BigIntegers.asUnsignedByteArray(this.N, r);
            digest.update(rBytes, 0, rBytes.length);
        }
        else
        {
            // Compute Y = HS*PVT + KPAK
            Y = pvt.multiply(HS).add(kpak).normalize();
        }
    }
}
