package org.bouncycastle.pqc.crypto.qtesla;

import java.util.Arrays;

import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.encoders.Hex;

public class FederalInformationProcessingStandard202
{

    public static final int SECURE_HASH_ALGORITHM_KECCAK_128_RATE = 168;
    public static final int SECURE_HASH_ALGORITHM_KECCAK_256_RATE = 136;
    public static final int SECURE_HASH_ALGORITHM_3_256_RATE = 136;
    public static final int NUMBER_OF_ROUND = 24;

    public static final long[] KECCAK_F_ROUND_CONSTANT = {

        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
        0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L

    };

    /***************************************************************************************************************************************************************
     * Description:	The Secure-Hash-Algorithm-3 Extendable-Output Function That Generally Supports 128 Bits of Security Strength, If the Output is Sufficiently Long
     ***************************************************************************************************************************************************************/
    public static void secureHashAlgorithmKECCAK128(byte[] output, int outputOffset, int outputLength, byte[] input, int inputOffset, int inputLength)
    {
        SHAKEDigest dig = new SHAKEDigest(128);
        dig.update(input, inputOffset, inputLength);

        dig.doFinal(output, outputOffset, outputLength);
    }

    /***************************************************************************************************************************************************************
     * Description:	The Secure-Hash-Algorithm-3 Extendable-Output Function That Generally Supports 256 Bits of Security Strength, If the Output is Sufficiently Long
     ***************************************************************************************************************************************************************/
    public static void secureHashAlgorithmKECCAK256(byte[] output, int outputOffset, int outputLength, byte[] input, int inputOffset, int inputLength)
    {
        SHAKEDigest dig = new SHAKEDigest(256);
        dig.update(input, inputOffset, inputLength);

        dig.doFinal(output, outputOffset, outputLength);
    }

    /* Customizable Secure Hash Algorithm KECCAK 128 / Customizable Secure Hash Algorithm KECCAK 256 */


    public static void customizableSecureHashAlgorithmKECCAK128Simple(byte[] output, int outputOffset, int outputLength, short continuousTimeStochasticModelling, byte[] input, int inputOffset, int inputLength)
    {
        CSHAKEDigest dig = new CSHAKEDigest(128, null, new byte[] {(byte)continuousTimeStochasticModelling, (byte)(continuousTimeStochasticModelling >> 8) });
        dig.update(input, inputOffset, inputLength);

        dig.doFinal(output, outputOffset, outputLength);
    }

    public static void customizableSecureHashAlgorithmKECCAK256Simple(byte[] output, int outputOffset, int outputLength, short continuousTimeStochasticModelling, byte[] input, int inputOffset, int inputLength)
    {
        CSHAKEDigest dig = new CSHAKEDigest(256, null, new byte[] {(byte)continuousTimeStochasticModelling, (byte)(continuousTimeStochasticModelling >> 8) });
        dig.update(input, inputOffset, inputLength);

        dig.doFinal(output, outputOffset, outputLength);
    }

}
