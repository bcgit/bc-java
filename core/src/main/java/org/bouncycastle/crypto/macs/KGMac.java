package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * The GMAC specialisation of Galois/Counter mode (GCM) detailed in NIST Special Publication
 * 800-38D as adapted for the Kalyna version of GCM.
 * <p>
 * KGMac is an invocation of the KGCM mode where no data is encrypted (i.e. all input data to the Mac
 * is processed as additional authenticated data with the underlying KGCM block cipher).
 */
public class KGMac
    implements Mac
{
    private final KGCMBlockCipher cipher;
    private final int macSizeBits;

    /**
     * Creates a KGMAC based on the operation of a block cipher in GCM mode.
     * <p>
     * This will produce an authentication code the length of the block size of the cipher.
     *
     * @param cipher
     *            the cipher to be used in GCM mode to generate the MAC.
     */
    public KGMac(final KGCMBlockCipher cipher)
    {
        // use of this confused flow analyser in some earlier JDKs
        this.cipher = cipher;
        this.macSizeBits = cipher.getUnderlyingCipher().getBlockSize() * 8;
    }

    /**
     * Creates a GMAC based on the operation of a 128 bit block cipher in GCM mode.
     *
     * @param macSizeBits
     *            the mac size to generate, in bits. Must be a multiple of 8 and &gt;= 32 and &lt;= 128.
     *            Sizes less than 96 are not recommended, but are supported for specialized applications.
     * @param cipher
     *            the cipher to be used in GCM mode to generate the MAC.
     */
    public KGMac(final KGCMBlockCipher cipher, final int macSizeBits)
    {
        this.cipher = cipher;
        this.macSizeBits = macSizeBits;
    }

    /**
     * Initialises the GMAC - requires a {@link ParametersWithIV} providing a {@link KeyParameter}
     * and a nonce.
     */
    public void init(final CipherParameters params) throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            final ParametersWithIV param = (ParametersWithIV)params;

            final byte[] iv = param.getIV();
            final KeyParameter keyParam = (KeyParameter)param.getParameters();

            // GCM is always operated in encrypt mode to calculate MAC
            cipher.init(true, new AEADParameters(keyParam, macSizeBits, iv));
        }
        else
        {
            throw new IllegalArgumentException("KGMAC requires ParametersWithIV");
        }
    }

    public String getAlgorithmName()
    {
        return cipher.getUnderlyingCipher().getAlgorithmName() + "-KGMAC";
    }

    public int getMacSize()
    {
        return macSizeBits / 8;
    }

    public void update(byte in) throws IllegalStateException
    {
        cipher.processAADByte(in);
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        cipher.processAADBytes(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        try
        {
            return cipher.doFinal(out, outOff);
        }
        catch (InvalidCipherTextException e)
        {
            // Impossible in encrypt mode
            throw new IllegalStateException(e.toString());
        }
    }

    public void reset()
    {
        cipher.reset();
    }
}
