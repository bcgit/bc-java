package org.bouncycastle.bcpg;

import java.io.IOException;

public class HashAlgorithmUtils implements HashAlgorithmTags {

    public static String getHashAlgorithmName(int algorithmId) {
        switch (algorithmId)
        {
            case MD5:
                return "MD5";
            case SHA1:
                return "SHA1";
            case RIPEMD160:
                return "RIPEMD160";
            case MD2:
                return "MD2";
            case SHA256:
                return "SHA256";
            case SHA384:
                return "SHA384";
            case SHA512:
                return "SHA512";
            case SHA224:
                return "SHA224";
            case SHA3_256:
            case SHA3_256_OLD:
                return "SHA3-256";
            case SHA3_384: // OLD
                return "SHA3-384";
            case SHA3_512:
            case SHA3_512_OLD:
                return "SHA3-512";
            case SHA3_224:
                return "SHA3-224";
            default:
                throw new IllegalArgumentException("unknown hash algorithm tag:" + algorithmId);
        }
    }
}
