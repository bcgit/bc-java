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
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECCSIPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECCSIPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class ECCSISigner
    implements Signer
{
    private static final BigInteger q;
    private static final ECPoint G;

    static
    {
        X9ECParameters params = CustomNamedCurves.getByName("secP256r1");
        q = params.getCurve().getOrder();
        G = params.getG();
    }

    private final Digest digest = new SHA256Digest();
    private BigInteger j;
    private BigInteger r;
    private ECPoint Y;
    private final ECPoint kpak;
    private final byte[] id;
    private CipherParameters param;
    private ByteArrayOutputStream stream;
    private boolean forSigning;

    public ECCSISigner(ECPoint kpak, byte[] id)
    {
        this.kpak = kpak;
        this.id = id;
    }

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        this.forSigning = forSigning;
        this.param = param;
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

            j = new BigInteger(256, random).mod(q);
            ECPoint J = G.multiply(j).normalize();
            r = J.getAffineXCoord().toBigInteger();
            pvt = parameters.getPublicKeyParameters().getPVT();
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
            byte[] rBytes = BigIntegers.asUnsignedByteArray(32, r);
            digest.update(rBytes, 0, rBytes.length);
        }
        else
        {
            // Compute Y = HS*PVT + KPAK
            Y = pvt.multiply(HS).add(kpak).normalize();
        }
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

        return Arrays.concatenate(BigIntegers.asUnsignedByteArray(32, r), BigIntegers.asUnsignedByteArray(32, sPrime),
            params.getPublicKeyParameters().getPVT().getEncoded(false));
    }

    @Override
    public boolean verifySignature(byte[] signature)
    {
        byte[] bytes = Arrays.copyOf(signature, 32);
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
        r = new BigInteger(1, bytes).mod(q);
        digest.update(bytes, 0, 32);
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

    @Override
    public void reset()
    {

    }
}
