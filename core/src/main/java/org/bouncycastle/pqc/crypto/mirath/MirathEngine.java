package org.bouncycastle.pqc.crypto.mirath;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.GF16;
import org.bouncycastle.util.Pack;

class MirathEngine
{
    public final int securityBytes;
    public final int saltBytes;
    public final int m;
    public final int r;
    final int n1;
    public final int k;
    final int tau;
    final int rho;
    final boolean isA;
    final int ffYBytes;
    final int ffSBytes;
    final int ffCBytes;
    final int ffHBytes;
    final int ffAuxBytes;
    final int baseMid;
    /**
     * m * m - k
     */
    final int eA;
    final int s;
    final int mu;
    final int c;
    private final int offEA;
    private final int offEB;
    final int treeLeaves;
    final int blockLength;
    final int challenge2Bytes;
    final int hash2MaskBytes;
    final int hash2Mask;
    final int tOpen;
    private final int leavesSeedsOffset;
    final int maxOpen;
    final int gamma;
    final int n1Bytes;
    final int n1Bits;
    final int n1Mask;
    final int signatureBytes;
    final boolean isFast;
    static final byte domainSeparatorCommitment = 5;
    private static final byte domainSeparatorPrg = 4;
    private static final byte domainSeparatorCmt = 3;
    SHAKEDigest prng;
    int nRowsBytes1;
    int nRowsBytes2;
    int onCol1;
    int onCol2;
    int ptr;
    int col;
    private static final byte[] MIRATH_MAP_FF_TO_FF_MU = new byte[]{
        (byte)0, (byte)1, (byte)92, (byte)93, (byte)224, (byte)225, (byte)188, (byte)189, (byte)80, (byte)81, (byte)12, (byte)13, (byte)176, (byte)177, (byte)236, (byte)237
    };

    private static final byte[] MIRATH_FF_MU_MULT_BASE = new byte[]{
        // row_nr**1, row_nr**2, ..., row_nr**8
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80,
        (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b,
        (byte)0x03, (byte)0x06, (byte)0x0c, (byte)0x18, (byte)0x30, (byte)0x60, (byte)0xc0, (byte)0x9b,
        (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36,
        (byte)0x05, (byte)0x0a, (byte)0x14, (byte)0x28, (byte)0x50, (byte)0xa0, (byte)0x5b, (byte)0xb6,
        (byte)0x06, (byte)0x0c, (byte)0x18, (byte)0x30, (byte)0x60, (byte)0xc0, (byte)0x9b, (byte)0x2d,
        (byte)0x07, (byte)0x0e, (byte)0x1c, (byte)0x38, (byte)0x70, (byte)0xe0, (byte)0xdb, (byte)0xad,
        (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c,
        (byte)0x09, (byte)0x12, (byte)0x24, (byte)0x48, (byte)0x90, (byte)0x3b, (byte)0x76, (byte)0xec,
        (byte)0x0a, (byte)0x14, (byte)0x28, (byte)0x50, (byte)0xa0, (byte)0x5b, (byte)0xb6, (byte)0x77,
        (byte)0x0b, (byte)0x16, (byte)0x2c, (byte)0x58, (byte)0xb0, (byte)0x7b, (byte)0xf6, (byte)0xf7,
        (byte)0x0c, (byte)0x18, (byte)0x30, (byte)0x60, (byte)0xc0, (byte)0x9b, (byte)0x2d, (byte)0x5a,
        (byte)0x0d, (byte)0x1a, (byte)0x34, (byte)0x68, (byte)0xd0, (byte)0xbb, (byte)0x6d, (byte)0xda,
        (byte)0x0e, (byte)0x1c, (byte)0x38, (byte)0x70, (byte)0xe0, (byte)0xdb, (byte)0xad, (byte)0x41,
        (byte)0x0f, (byte)0x1e, (byte)0x3c, (byte)0x78, (byte)0xf0, (byte)0xfb, (byte)0xed, (byte)0xc1,
        (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c, (byte)0xd8,
        (byte)0x11, (byte)0x22, (byte)0x44, (byte)0x88, (byte)0x0b, (byte)0x16, (byte)0x2c, (byte)0x58,
        (byte)0x12, (byte)0x24, (byte)0x48, (byte)0x90, (byte)0x3b, (byte)0x76, (byte)0xec, (byte)0xc3,
        (byte)0x13, (byte)0x26, (byte)0x4c, (byte)0x98, (byte)0x2b, (byte)0x56, (byte)0xac, (byte)0x43,
        (byte)0x14, (byte)0x28, (byte)0x50, (byte)0xa0, (byte)0x5b, (byte)0xb6, (byte)0x77, (byte)0xee,
        (byte)0x15, (byte)0x2a, (byte)0x54, (byte)0xa8, (byte)0x4b, (byte)0x96, (byte)0x37, (byte)0x6e,
        (byte)0x16, (byte)0x2c, (byte)0x58, (byte)0xb0, (byte)0x7b, (byte)0xf6, (byte)0xf7, (byte)0xf5,
        (byte)0x17, (byte)0x2e, (byte)0x5c, (byte)0xb8, (byte)0x6b, (byte)0xd6, (byte)0xb7, (byte)0x75,
        (byte)0x18, (byte)0x30, (byte)0x60, (byte)0xc0, (byte)0x9b, (byte)0x2d, (byte)0x5a, (byte)0xb4,
        (byte)0x19, (byte)0x32, (byte)0x64, (byte)0xc8, (byte)0x8b, (byte)0x0d, (byte)0x1a, (byte)0x34,
        (byte)0x1a, (byte)0x34, (byte)0x68, (byte)0xd0, (byte)0xbb, (byte)0x6d, (byte)0xda, (byte)0xaf,
        (byte)0x1b, (byte)0x36, (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f,
        (byte)0x1c, (byte)0x38, (byte)0x70, (byte)0xe0, (byte)0xdb, (byte)0xad, (byte)0x41, (byte)0x82,
        (byte)0x1d, (byte)0x3a, (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, (byte)0x01, (byte)0x02,
        (byte)0x1e, (byte)0x3c, (byte)0x78, (byte)0xf0, (byte)0xfb, (byte)0xed, (byte)0xc1, (byte)0x99,
        (byte)0x1f, (byte)0x3e, (byte)0x7c, (byte)0xf8, (byte)0xeb, (byte)0xcd, (byte)0x81, (byte)0x19,
        (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c, (byte)0xd8, (byte)0xab,
        (byte)0x21, (byte)0x42, (byte)0x84, (byte)0x13, (byte)0x26, (byte)0x4c, (byte)0x98, (byte)0x2b,
        (byte)0x22, (byte)0x44, (byte)0x88, (byte)0x0b, (byte)0x16, (byte)0x2c, (byte)0x58, (byte)0xb0,
        (byte)0x23, (byte)0x46, (byte)0x8c, (byte)0x03, (byte)0x06, (byte)0x0c, (byte)0x18, (byte)0x30,
        (byte)0x24, (byte)0x48, (byte)0x90, (byte)0x3b, (byte)0x76, (byte)0xec, (byte)0xc3, (byte)0x9d,
        (byte)0x25, (byte)0x4a, (byte)0x94, (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d,
        (byte)0x26, (byte)0x4c, (byte)0x98, (byte)0x2b, (byte)0x56, (byte)0xac, (byte)0x43, (byte)0x86,
        (byte)0x27, (byte)0x4e, (byte)0x9c, (byte)0x23, (byte)0x46, (byte)0x8c, (byte)0x03, (byte)0x06,
        (byte)0x28, (byte)0x50, (byte)0xa0, (byte)0x5b, (byte)0xb6, (byte)0x77, (byte)0xee, (byte)0xc7,
        (byte)0x29, (byte)0x52, (byte)0xa4, (byte)0x53, (byte)0xa6, (byte)0x57, (byte)0xae, (byte)0x47,
        (byte)0x2a, (byte)0x54, (byte)0xa8, (byte)0x4b, (byte)0x96, (byte)0x37, (byte)0x6e, (byte)0xdc,
        (byte)0x2b, (byte)0x56, (byte)0xac, (byte)0x43, (byte)0x86, (byte)0x17, (byte)0x2e, (byte)0x5c,
        (byte)0x2c, (byte)0x58, (byte)0xb0, (byte)0x7b, (byte)0xf6, (byte)0xf7, (byte)0xf5, (byte)0xf1,
        (byte)0x2d, (byte)0x5a, (byte)0xb4, (byte)0x73, (byte)0xe6, (byte)0xd7, (byte)0xb5, (byte)0x71,
        (byte)0x2e, (byte)0x5c, (byte)0xb8, (byte)0x6b, (byte)0xd6, (byte)0xb7, (byte)0x75, (byte)0xea,
        (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a,
        (byte)0x30, (byte)0x60, (byte)0xc0, (byte)0x9b, (byte)0x2d, (byte)0x5a, (byte)0xb4, (byte)0x73,
        (byte)0x31, (byte)0x62, (byte)0xc4, (byte)0x93, (byte)0x3d, (byte)0x7a, (byte)0xf4, (byte)0xf3,
        (byte)0x32, (byte)0x64, (byte)0xc8, (byte)0x8b, (byte)0x0d, (byte)0x1a, (byte)0x34, (byte)0x68,
        (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a, (byte)0x74, (byte)0xe8,
        (byte)0x34, (byte)0x68, (byte)0xd0, (byte)0xbb, (byte)0x6d, (byte)0xda, (byte)0xaf, (byte)0x45,
        (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5,
        (byte)0x36, (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e,
        (byte)0x37, (byte)0x6e, (byte)0xdc, (byte)0xa3, (byte)0x5d, (byte)0xba, (byte)0x6f, (byte)0xde,
        (byte)0x38, (byte)0x70, (byte)0xe0, (byte)0xdb, (byte)0xad, (byte)0x41, (byte)0x82, (byte)0x1f,
        (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, (byte)0x61, (byte)0xc2, (byte)0x9f,
        (byte)0x3a, (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04,
        (byte)0x3b, (byte)0x76, (byte)0xec, (byte)0xc3, (byte)0x9d, (byte)0x21, (byte)0x42, (byte)0x84,
        (byte)0x3c, (byte)0x78, (byte)0xf0, (byte)0xfb, (byte)0xed, (byte)0xc1, (byte)0x99, (byte)0x29,
        (byte)0x3d, (byte)0x7a, (byte)0xf4, (byte)0xf3, (byte)0xfd, (byte)0xe1, (byte)0xd9, (byte)0xa9,
        (byte)0x3e, (byte)0x7c, (byte)0xf8, (byte)0xeb, (byte)0xcd, (byte)0x81, (byte)0x19, (byte)0x32,
        (byte)0x3f, (byte)0x7e, (byte)0xfc, (byte)0xe3, (byte)0xdd, (byte)0xa1, (byte)0x59, (byte)0xb2,
        (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d,
        (byte)0x41, (byte)0x82, (byte)0x1f, (byte)0x3e, (byte)0x7c, (byte)0xf8, (byte)0xeb, (byte)0xcd,
        (byte)0x42, (byte)0x84, (byte)0x13, (byte)0x26, (byte)0x4c, (byte)0x98, (byte)0x2b, (byte)0x56,
        (byte)0x43, (byte)0x86, (byte)0x17, (byte)0x2e, (byte)0x5c, (byte)0xb8, (byte)0x6b, (byte)0xd6,
        (byte)0x44, (byte)0x88, (byte)0x0b, (byte)0x16, (byte)0x2c, (byte)0x58, (byte)0xb0, (byte)0x7b,
        (byte)0x45, (byte)0x8a, (byte)0x0f, (byte)0x1e, (byte)0x3c, (byte)0x78, (byte)0xf0, (byte)0xfb,
        (byte)0x46, (byte)0x8c, (byte)0x03, (byte)0x06, (byte)0x0c, (byte)0x18, (byte)0x30, (byte)0x60,
        (byte)0x47, (byte)0x8e, (byte)0x07, (byte)0x0e, (byte)0x1c, (byte)0x38, (byte)0x70, (byte)0xe0,
        (byte)0x48, (byte)0x90, (byte)0x3b, (byte)0x76, (byte)0xec, (byte)0xc3, (byte)0x9d, (byte)0x21,
        (byte)0x49, (byte)0x92, (byte)0x3f, (byte)0x7e, (byte)0xfc, (byte)0xe3, (byte)0xdd, (byte)0xa1,
        (byte)0x4a, (byte)0x94, (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a,
        (byte)0x4b, (byte)0x96, (byte)0x37, (byte)0x6e, (byte)0xdc, (byte)0xa3, (byte)0x5d, (byte)0xba,
        (byte)0x4c, (byte)0x98, (byte)0x2b, (byte)0x56, (byte)0xac, (byte)0x43, (byte)0x86, (byte)0x17,
        (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97,
        (byte)0x4e, (byte)0x9c, (byte)0x23, (byte)0x46, (byte)0x8c, (byte)0x03, (byte)0x06, (byte)0x0c,
        (byte)0x4f, (byte)0x9e, (byte)0x27, (byte)0x4e, (byte)0x9c, (byte)0x23, (byte)0x46, (byte)0x8c,
        (byte)0x50, (byte)0xa0, (byte)0x5b, (byte)0xb6, (byte)0x77, (byte)0xee, (byte)0xc7, (byte)0x95,
        (byte)0x51, (byte)0xa2, (byte)0x5f, (byte)0xbe, (byte)0x67, (byte)0xce, (byte)0x87, (byte)0x15,
        (byte)0x52, (byte)0xa4, (byte)0x53, (byte)0xa6, (byte)0x57, (byte)0xae, (byte)0x47, (byte)0x8e,
        (byte)0x53, (byte)0xa6, (byte)0x57, (byte)0xae, (byte)0x47, (byte)0x8e, (byte)0x07, (byte)0x0e,
        (byte)0x54, (byte)0xa8, (byte)0x4b, (byte)0x96, (byte)0x37, (byte)0x6e, (byte)0xdc, (byte)0xa3,
        (byte)0x55, (byte)0xaa, (byte)0x4f, (byte)0x9e, (byte)0x27, (byte)0x4e, (byte)0x9c, (byte)0x23,
        (byte)0x56, (byte)0xac, (byte)0x43, (byte)0x86, (byte)0x17, (byte)0x2e, (byte)0x5c, (byte)0xb8,
        (byte)0x57, (byte)0xae, (byte)0x47, (byte)0x8e, (byte)0x07, (byte)0x0e, (byte)0x1c, (byte)0x38,
        (byte)0x58, (byte)0xb0, (byte)0x7b, (byte)0xf6, (byte)0xf7, (byte)0xf5, (byte)0xf1, (byte)0xf9,
        (byte)0x59, (byte)0xb2, (byte)0x7f, (byte)0xfe, (byte)0xe7, (byte)0xd5, (byte)0xb1, (byte)0x79,
        (byte)0x5a, (byte)0xb4, (byte)0x73, (byte)0xe6, (byte)0xd7, (byte)0xb5, (byte)0x71, (byte)0xe2,
        (byte)0x5b, (byte)0xb6, (byte)0x77, (byte)0xee, (byte)0xc7, (byte)0x95, (byte)0x31, (byte)0x62,
        (byte)0x5c, (byte)0xb8, (byte)0x6b, (byte)0xd6, (byte)0xb7, (byte)0x75, (byte)0xea, (byte)0xcf,
        (byte)0x5d, (byte)0xba, (byte)0x6f, (byte)0xde, (byte)0xa7, (byte)0x55, (byte)0xaa, (byte)0x4f,
        (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4,
        (byte)0x5f, (byte)0xbe, (byte)0x67, (byte)0xce, (byte)0x87, (byte)0x15, (byte)0x2a, (byte)0x54,
        (byte)0x60, (byte)0xc0, (byte)0x9b, (byte)0x2d, (byte)0x5a, (byte)0xb4, (byte)0x73, (byte)0xe6,
        (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94, (byte)0x33, (byte)0x66,
        (byte)0x62, (byte)0xc4, (byte)0x93, (byte)0x3d, (byte)0x7a, (byte)0xf4, (byte)0xf3, (byte)0xfd,
        (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3, (byte)0x7d,
        (byte)0x64, (byte)0xc8, (byte)0x8b, (byte)0x0d, (byte)0x1a, (byte)0x34, (byte)0x68, (byte)0xd0,
        (byte)0x65, (byte)0xca, (byte)0x8f, (byte)0x05, (byte)0x0a, (byte)0x14, (byte)0x28, (byte)0x50,
        (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a, (byte)0x74, (byte)0xe8, (byte)0xcb,
        (byte)0x67, (byte)0xce, (byte)0x87, (byte)0x15, (byte)0x2a, (byte)0x54, (byte)0xa8, (byte)0x4b,
        (byte)0x68, (byte)0xd0, (byte)0xbb, (byte)0x6d, (byte)0xda, (byte)0xaf, (byte)0x45, (byte)0x8a,
        (byte)0x69, (byte)0xd2, (byte)0xbf, (byte)0x65, (byte)0xca, (byte)0x8f, (byte)0x05, (byte)0x0a,
        (byte)0x6a, (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91,
        (byte)0x6b, (byte)0xd6, (byte)0xb7, (byte)0x75, (byte)0xea, (byte)0xcf, (byte)0x85, (byte)0x11,
        (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e, (byte)0xbc,
        (byte)0x6d, (byte)0xda, (byte)0xaf, (byte)0x45, (byte)0x8a, (byte)0x0f, (byte)0x1e, (byte)0x3c,
        (byte)0x6e, (byte)0xdc, (byte)0xa3, (byte)0x5d, (byte)0xba, (byte)0x6f, (byte)0xde, (byte)0xa7,
        (byte)0x6f, (byte)0xde, (byte)0xa7, (byte)0x55, (byte)0xaa, (byte)0x4f, (byte)0x9e, (byte)0x27,
        (byte)0x70, (byte)0xe0, (byte)0xdb, (byte)0xad, (byte)0x41, (byte)0x82, (byte)0x1f, (byte)0x3e,
        (byte)0x71, (byte)0xe2, (byte)0xdf, (byte)0xa5, (byte)0x51, (byte)0xa2, (byte)0x5f, (byte)0xbe,
        (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25,
        (byte)0x73, (byte)0xe6, (byte)0xd7, (byte)0xb5, (byte)0x71, (byte)0xe2, (byte)0xdf, (byte)0xa5,
        (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08,
        (byte)0x75, (byte)0xea, (byte)0xcf, (byte)0x85, (byte)0x11, (byte)0x22, (byte)0x44, (byte)0x88,
        (byte)0x76, (byte)0xec, (byte)0xc3, (byte)0x9d, (byte)0x21, (byte)0x42, (byte)0x84, (byte)0x13,
        (byte)0x77, (byte)0xee, (byte)0xc7, (byte)0x95, (byte)0x31, (byte)0x62, (byte)0xc4, (byte)0x93,
        (byte)0x78, (byte)0xf0, (byte)0xfb, (byte)0xed, (byte)0xc1, (byte)0x99, (byte)0x29, (byte)0x52,
        (byte)0x79, (byte)0xf2, (byte)0xff, (byte)0xe5, (byte)0xd1, (byte)0xb9, (byte)0x69, (byte)0xd2,
        (byte)0x7a, (byte)0xf4, (byte)0xf3, (byte)0xfd, (byte)0xe1, (byte)0xd9, (byte)0xa9, (byte)0x49,
        (byte)0x7b, (byte)0xf6, (byte)0xf7, (byte)0xf5, (byte)0xf1, (byte)0xf9, (byte)0xe9, (byte)0xc9,
        (byte)0x7c, (byte)0xf8, (byte)0xeb, (byte)0xcd, (byte)0x81, (byte)0x19, (byte)0x32, (byte)0x64,
        (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4,
        (byte)0x7e, (byte)0xfc, (byte)0xe3, (byte)0xdd, (byte)0xa1, (byte)0x59, (byte)0xb2, (byte)0x7f,
        (byte)0x7f, (byte)0xfe, (byte)0xe7, (byte)0xd5, (byte)0xb1, (byte)0x79, (byte)0xf2, (byte)0xff,
        (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a,
        (byte)0x81, (byte)0x19, (byte)0x32, (byte)0x64, (byte)0xc8, (byte)0x8b, (byte)0x0d, (byte)0x1a,
        (byte)0x82, (byte)0x1f, (byte)0x3e, (byte)0x7c, (byte)0xf8, (byte)0xeb, (byte)0xcd, (byte)0x81,
        (byte)0x83, (byte)0x1d, (byte)0x3a, (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, (byte)0x01,
        (byte)0x84, (byte)0x13, (byte)0x26, (byte)0x4c, (byte)0x98, (byte)0x2b, (byte)0x56, (byte)0xac,
        (byte)0x85, (byte)0x11, (byte)0x22, (byte)0x44, (byte)0x88, (byte)0x0b, (byte)0x16, (byte)0x2c,
        (byte)0x86, (byte)0x17, (byte)0x2e, (byte)0x5c, (byte)0xb8, (byte)0x6b, (byte)0xd6, (byte)0xb7,
        (byte)0x87, (byte)0x15, (byte)0x2a, (byte)0x54, (byte)0xa8, (byte)0x4b, (byte)0x96, (byte)0x37,
        (byte)0x88, (byte)0x0b, (byte)0x16, (byte)0x2c, (byte)0x58, (byte)0xb0, (byte)0x7b, (byte)0xf6,
        (byte)0x89, (byte)0x09, (byte)0x12, (byte)0x24, (byte)0x48, (byte)0x90, (byte)0x3b, (byte)0x76,
        (byte)0x8a, (byte)0x0f, (byte)0x1e, (byte)0x3c, (byte)0x78, (byte)0xf0, (byte)0xfb, (byte)0xed,
        (byte)0x8b, (byte)0x0d, (byte)0x1a, (byte)0x34, (byte)0x68, (byte)0xd0, (byte)0xbb, (byte)0x6d,
        (byte)0x8c, (byte)0x03, (byte)0x06, (byte)0x0c, (byte)0x18, (byte)0x30, (byte)0x60, (byte)0xc0,
        (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40,
        (byte)0x8e, (byte)0x07, (byte)0x0e, (byte)0x1c, (byte)0x38, (byte)0x70, (byte)0xe0, (byte)0xdb,
        (byte)0x8f, (byte)0x05, (byte)0x0a, (byte)0x14, (byte)0x28, (byte)0x50, (byte)0xa0, (byte)0x5b,
        (byte)0x90, (byte)0x3b, (byte)0x76, (byte)0xec, (byte)0xc3, (byte)0x9d, (byte)0x21, (byte)0x42,
        (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, (byte)0x61, (byte)0xc2,
        (byte)0x92, (byte)0x3f, (byte)0x7e, (byte)0xfc, (byte)0xe3, (byte)0xdd, (byte)0xa1, (byte)0x59,
        (byte)0x93, (byte)0x3d, (byte)0x7a, (byte)0xf4, (byte)0xf3, (byte)0xfd, (byte)0xe1, (byte)0xd9,
        (byte)0x94, (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a, (byte)0x74,
        (byte)0x95, (byte)0x31, (byte)0x62, (byte)0xc4, (byte)0x93, (byte)0x3d, (byte)0x7a, (byte)0xf4,
        (byte)0x96, (byte)0x37, (byte)0x6e, (byte)0xdc, (byte)0xa3, (byte)0x5d, (byte)0xba, (byte)0x6f,
        (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef,
        (byte)0x98, (byte)0x2b, (byte)0x56, (byte)0xac, (byte)0x43, (byte)0x86, (byte)0x17, (byte)0x2e,
        (byte)0x99, (byte)0x29, (byte)0x52, (byte)0xa4, (byte)0x53, (byte)0xa6, (byte)0x57, (byte)0xae,
        (byte)0x9a, (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35,
        (byte)0x9b, (byte)0x2d, (byte)0x5a, (byte)0xb4, (byte)0x73, (byte)0xe6, (byte)0xd7, (byte)0xb5,
        (byte)0x9c, (byte)0x23, (byte)0x46, (byte)0x8c, (byte)0x03, (byte)0x06, (byte)0x0c, (byte)0x18,
        (byte)0x9d, (byte)0x21, (byte)0x42, (byte)0x84, (byte)0x13, (byte)0x26, (byte)0x4c, (byte)0x98,
        (byte)0x9e, (byte)0x27, (byte)0x4e, (byte)0x9c, (byte)0x23, (byte)0x46, (byte)0x8c, (byte)0x03,
        (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94, (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83,
        (byte)0xa0, (byte)0x5b, (byte)0xb6, (byte)0x77, (byte)0xee, (byte)0xc7, (byte)0x95, (byte)0x31,
        (byte)0xa1, (byte)0x59, (byte)0xb2, (byte)0x7f, (byte)0xfe, (byte)0xe7, (byte)0xd5, (byte)0xb1,
        (byte)0xa2, (byte)0x5f, (byte)0xbe, (byte)0x67, (byte)0xce, (byte)0x87, (byte)0x15, (byte)0x2a,
        (byte)0xa3, (byte)0x5d, (byte)0xba, (byte)0x6f, (byte)0xde, (byte)0xa7, (byte)0x55, (byte)0xaa,
        (byte)0xa4, (byte)0x53, (byte)0xa6, (byte)0x57, (byte)0xae, (byte)0x47, (byte)0x8e, (byte)0x07,
        (byte)0xa5, (byte)0x51, (byte)0xa2, (byte)0x5f, (byte)0xbe, (byte)0x67, (byte)0xce, (byte)0x87,
        (byte)0xa6, (byte)0x57, (byte)0xae, (byte)0x47, (byte)0x8e, (byte)0x07, (byte)0x0e, (byte)0x1c,
        (byte)0xa7, (byte)0x55, (byte)0xaa, (byte)0x4f, (byte)0x9e, (byte)0x27, (byte)0x4e, (byte)0x9c,
        (byte)0xa8, (byte)0x4b, (byte)0x96, (byte)0x37, (byte)0x6e, (byte)0xdc, (byte)0xa3, (byte)0x5d,
        (byte)0xa9, (byte)0x49, (byte)0x92, (byte)0x3f, (byte)0x7e, (byte)0xfc, (byte)0xe3, (byte)0xdd,
        (byte)0xaa, (byte)0x4f, (byte)0x9e, (byte)0x27, (byte)0x4e, (byte)0x9c, (byte)0x23, (byte)0x46,
        (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6,
        (byte)0xac, (byte)0x43, (byte)0x86, (byte)0x17, (byte)0x2e, (byte)0x5c, (byte)0xb8, (byte)0x6b,
        (byte)0xad, (byte)0x41, (byte)0x82, (byte)0x1f, (byte)0x3e, (byte)0x7c, (byte)0xf8, (byte)0xeb,
        (byte)0xae, (byte)0x47, (byte)0x8e, (byte)0x07, (byte)0x0e, (byte)0x1c, (byte)0x38, (byte)0x70,
        (byte)0xaf, (byte)0x45, (byte)0x8a, (byte)0x0f, (byte)0x1e, (byte)0x3c, (byte)0x78, (byte)0xf0,
        (byte)0xb0, (byte)0x7b, (byte)0xf6, (byte)0xf7, (byte)0xf5, (byte)0xf1, (byte)0xf9, (byte)0xe9,
        (byte)0xb1, (byte)0x79, (byte)0xf2, (byte)0xff, (byte)0xe5, (byte)0xd1, (byte)0xb9, (byte)0x69,
        (byte)0xb2, (byte)0x7f, (byte)0xfe, (byte)0xe7, (byte)0xd5, (byte)0xb1, (byte)0x79, (byte)0xf2,
        (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, (byte)0x39, (byte)0x72,
        (byte)0xb4, (byte)0x73, (byte)0xe6, (byte)0xd7, (byte)0xb5, (byte)0x71, (byte)0xe2, (byte)0xdf,
        (byte)0xb5, (byte)0x71, (byte)0xe2, (byte)0xdf, (byte)0xa5, (byte)0x51, (byte)0xa2, (byte)0x5f,
        (byte)0xb6, (byte)0x77, (byte)0xee, (byte)0xc7, (byte)0x95, (byte)0x31, (byte)0x62, (byte)0xc4,
        (byte)0xb7, (byte)0x75, (byte)0xea, (byte)0xcf, (byte)0x85, (byte)0x11, (byte)0x22, (byte)0x44,
        (byte)0xb8, (byte)0x6b, (byte)0xd6, (byte)0xb7, (byte)0x75, (byte)0xea, (byte)0xcf, (byte)0x85,
        (byte)0xb9, (byte)0x69, (byte)0xd2, (byte)0xbf, (byte)0x65, (byte)0xca, (byte)0x8f, (byte)0x05,
        (byte)0xba, (byte)0x6f, (byte)0xde, (byte)0xa7, (byte)0x55, (byte)0xaa, (byte)0x4f, (byte)0x9e,
        (byte)0xbb, (byte)0x6d, (byte)0xda, (byte)0xaf, (byte)0x45, (byte)0x8a, (byte)0x0f, (byte)0x1e,
        (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3,
        (byte)0xbd, (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94, (byte)0x33,
        (byte)0xbe, (byte)0x67, (byte)0xce, (byte)0x87, (byte)0x15, (byte)0x2a, (byte)0x54, (byte)0xa8,
        (byte)0xbf, (byte)0x65, (byte)0xca, (byte)0x8f, (byte)0x05, (byte)0x0a, (byte)0x14, (byte)0x28,
        (byte)0xc0, (byte)0x9b, (byte)0x2d, (byte)0x5a, (byte)0xb4, (byte)0x73, (byte)0xe6, (byte)0xd7,
        (byte)0xc1, (byte)0x99, (byte)0x29, (byte)0x52, (byte)0xa4, (byte)0x53, (byte)0xa6, (byte)0x57,
        (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94, (byte)0x33, (byte)0x66, (byte)0xcc,
        (byte)0xc3, (byte)0x9d, (byte)0x21, (byte)0x42, (byte)0x84, (byte)0x13, (byte)0x26, (byte)0x4c,
        (byte)0xc4, (byte)0x93, (byte)0x3d, (byte)0x7a, (byte)0xf4, (byte)0xf3, (byte)0xfd, (byte)0xe1,
        (byte)0xc5, (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, (byte)0x61,
        (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa,
        (byte)0xc7, (byte)0x95, (byte)0x31, (byte)0x62, (byte)0xc4, (byte)0x93, (byte)0x3d, (byte)0x7a,
        (byte)0xc8, (byte)0x8b, (byte)0x0d, (byte)0x1a, (byte)0x34, (byte)0x68, (byte)0xd0, (byte)0xbb,
        (byte)0xc9, (byte)0x89, (byte)0x09, (byte)0x12, (byte)0x24, (byte)0x48, (byte)0x90, (byte)0x3b,
        (byte)0xca, (byte)0x8f, (byte)0x05, (byte)0x0a, (byte)0x14, (byte)0x28, (byte)0x50, (byte)0xa0,
        (byte)0xcb, (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20,
        (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a, (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d,
        (byte)0xcd, (byte)0x81, (byte)0x19, (byte)0x32, (byte)0x64, (byte)0xc8, (byte)0x8b, (byte)0x0d,
        (byte)0xce, (byte)0x87, (byte)0x15, (byte)0x2a, (byte)0x54, (byte)0xa8, (byte)0x4b, (byte)0x96,
        (byte)0xcf, (byte)0x85, (byte)0x11, (byte)0x22, (byte)0x44, (byte)0x88, (byte)0x0b, (byte)0x16,
        (byte)0xd0, (byte)0xbb, (byte)0x6d, (byte)0xda, (byte)0xaf, (byte)0x45, (byte)0x8a, (byte)0x0f,
        (byte)0xd1, (byte)0xb9, (byte)0x69, (byte)0xd2, (byte)0xbf, (byte)0x65, (byte)0xca, (byte)0x8f,
        (byte)0xd2, (byte)0xbf, (byte)0x65, (byte)0xca, (byte)0x8f, (byte)0x05, (byte)0x0a, (byte)0x14,
        (byte)0xd3, (byte)0xbd, (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94,
        (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, (byte)0x39,
        (byte)0xd5, (byte)0xb1, (byte)0x79, (byte)0xf2, (byte)0xff, (byte)0xe5, (byte)0xd1, (byte)0xb9,
        (byte)0xd6, (byte)0xb7, (byte)0x75, (byte)0xea, (byte)0xcf, (byte)0x85, (byte)0x11, (byte)0x22,
        (byte)0xd7, (byte)0xb5, (byte)0x71, (byte)0xe2, (byte)0xdf, (byte)0xa5, (byte)0x51, (byte)0xa2,
        (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63,
        (byte)0xd9, (byte)0xa9, (byte)0x49, (byte)0x92, (byte)0x3f, (byte)0x7e, (byte)0xfc, (byte)0xe3,
        (byte)0xda, (byte)0xaf, (byte)0x45, (byte)0x8a, (byte)0x0f, (byte)0x1e, (byte)0x3c, (byte)0x78,
        (byte)0xdb, (byte)0xad, (byte)0x41, (byte)0x82, (byte)0x1f, (byte)0x3e, (byte)0x7c, (byte)0xf8,
        (byte)0xdc, (byte)0xa3, (byte)0x5d, (byte)0xba, (byte)0x6f, (byte)0xde, (byte)0xa7, (byte)0x55,
        (byte)0xdd, (byte)0xa1, (byte)0x59, (byte)0xb2, (byte)0x7f, (byte)0xfe, (byte)0xe7, (byte)0xd5,
        (byte)0xde, (byte)0xa7, (byte)0x55, (byte)0xaa, (byte)0x4f, (byte)0x9e, (byte)0x27, (byte)0x4e,
        (byte)0xdf, (byte)0xa5, (byte)0x51, (byte)0xa2, (byte)0x5f, (byte)0xbe, (byte)0x67, (byte)0xce,
        (byte)0xe0, (byte)0xdb, (byte)0xad, (byte)0x41, (byte)0x82, (byte)0x1f, (byte)0x3e, (byte)0x7c,
        (byte)0xe1, (byte)0xd9, (byte)0xa9, (byte)0x49, (byte)0x92, (byte)0x3f, (byte)0x7e, (byte)0xfc,
        (byte)0xe2, (byte)0xdf, (byte)0xa5, (byte)0x51, (byte)0xa2, (byte)0x5f, (byte)0xbe, (byte)0x67,
        (byte)0xe3, (byte)0xdd, (byte)0xa1, (byte)0x59, (byte)0xb2, (byte)0x7f, (byte)0xfe, (byte)0xe7,
        (byte)0xe4, (byte)0xd3, (byte)0xbd, (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a,
        (byte)0xe5, (byte)0xd1, (byte)0xb9, (byte)0x69, (byte)0xd2, (byte)0xbf, (byte)0x65, (byte)0xca,
        (byte)0xe6, (byte)0xd7, (byte)0xb5, (byte)0x71, (byte)0xe2, (byte)0xdf, (byte)0xa5, (byte)0x51,
        (byte)0xe7, (byte)0xd5, (byte)0xb1, (byte)0x79, (byte)0xf2, (byte)0xff, (byte)0xe5, (byte)0xd1,
        (byte)0xe8, (byte)0xcb, (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10,
        (byte)0xe9, (byte)0xc9, (byte)0x89, (byte)0x09, (byte)0x12, (byte)0x24, (byte)0x48, (byte)0x90,
        (byte)0xea, (byte)0xcf, (byte)0x85, (byte)0x11, (byte)0x22, (byte)0x44, (byte)0x88, (byte)0x0b,
        (byte)0xeb, (byte)0xcd, (byte)0x81, (byte)0x19, (byte)0x32, (byte)0x64, (byte)0xc8, (byte)0x8b,
        (byte)0xec, (byte)0xc3, (byte)0x9d, (byte)0x21, (byte)0x42, (byte)0x84, (byte)0x13, (byte)0x26,
        (byte)0xed, (byte)0xc1, (byte)0x99, (byte)0x29, (byte)0x52, (byte)0xa4, (byte)0x53, (byte)0xa6,
        (byte)0xee, (byte)0xc7, (byte)0x95, (byte)0x31, (byte)0x62, (byte)0xc4, (byte)0x93, (byte)0x3d,
        (byte)0xef, (byte)0xc5, (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd,
        (byte)0xf0, (byte)0xfb, (byte)0xed, (byte)0xc1, (byte)0x99, (byte)0x29, (byte)0x52, (byte)0xa4,
        (byte)0xf1, (byte)0xf9, (byte)0xe9, (byte)0xc9, (byte)0x89, (byte)0x09, (byte)0x12, (byte)0x24,
        (byte)0xf2, (byte)0xff, (byte)0xe5, (byte)0xd1, (byte)0xb9, (byte)0x69, (byte)0xd2, (byte)0xbf,
        (byte)0xf3, (byte)0xfd, (byte)0xe1, (byte)0xd9, (byte)0xa9, (byte)0x49, (byte)0x92, (byte)0x3f,
        (byte)0xf4, (byte)0xf3, (byte)0xfd, (byte)0xe1, (byte)0xd9, (byte)0xa9, (byte)0x49, (byte)0x92,
        (byte)0xf5, (byte)0xf1, (byte)0xf9, (byte)0xe9, (byte)0xc9, (byte)0x89, (byte)0x09, (byte)0x12,
        (byte)0xf6, (byte)0xf7, (byte)0xf5, (byte)0xf1, (byte)0xf9, (byte)0xe9, (byte)0xc9, (byte)0x89,
        (byte)0xf7, (byte)0xf5, (byte)0xf1, (byte)0xf9, (byte)0xe9, (byte)0xc9, (byte)0x89, (byte)0x09,
        (byte)0xf8, (byte)0xeb, (byte)0xcd, (byte)0x81, (byte)0x19, (byte)0x32, (byte)0x64, (byte)0xc8,
        (byte)0xf9, (byte)0xe9, (byte)0xc9, (byte)0x89, (byte)0x09, (byte)0x12, (byte)0x24, (byte)0x48,
        (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3,
        (byte)0xfb, (byte)0xed, (byte)0xc1, (byte)0x99, (byte)0x29, (byte)0x52, (byte)0xa4, (byte)0x53,
        (byte)0xfc, (byte)0xe3, (byte)0xdd, (byte)0xa1, (byte)0x59, (byte)0xb2, (byte)0x7f, (byte)0xfe,
        (byte)0xfd, (byte)0xe1, (byte)0xd9, (byte)0xa9, (byte)0x49, (byte)0x92, (byte)0x3f, (byte)0x7e,
        (byte)0xfe, (byte)0xe7, (byte)0xd5, (byte)0xb1, (byte)0x79, (byte)0xf2, (byte)0xff, (byte)0xe5,
        (byte)0xff, (byte)0xe5, (byte)0xd1, (byte)0xb9, (byte)0x69, (byte)0xd2, (byte)0xbf, (byte)0x65,
    };

    public MirathEngine(MirathParameters parameters)
    {
        securityBytes = parameters.getSecurityLevelBytes();
        saltBytes = parameters.getSaltBytes();
        m = parameters.getM();
        r = parameters.getR();
        n1 = parameters.getN1();
        rho = parameters.getRho();
        k = parameters.getK();
        isA = parameters.isA();
        tau = parameters.getTau();
        treeLeaves = parameters.getTreeLeaves();
        challenge2Bytes = parameters.getChallenge2Bytes();
        hash2MaskBytes = parameters.getHash2MaskBytes();
        hash2Mask = parameters.getHash2Mask();
        tOpen = parameters.getTOpen();
        n1Bytes = parameters.getN1Bytes();
        n1Bits = parameters.getN1Bits();
        n1Mask = parameters.getN1Mask();
        mu = parameters.getMu();
        isFast = parameters.isFast();
        signatureBytes = parameters.getSignatureBytes();
        leavesSeedsOffset = treeLeaves - 1;
        maxOpen = 2 * tOpen;
        eA = m * m - k;
        ffYBytes = mirathMatrixFFBytesSize(eA, 1);
        ffSBytes = mirathMatrixFFBytesSize(m, r);
        ffCBytes = mirathMatrixFFBytesSize(r, m - r);
        ffHBytes = mirathMatrixFFBytesSize(eA, k);
        ffAuxBytes = ffSBytes + ffCBytes;
        baseMid = m * (m - r);
        s = m * r;
        c = r * (m - r);
        gamma = rho * eA;
        blockLength = (ffSBytes + ffCBytes + rho + (securityBytes - 1)) / securityBytes;
        prng = new SHAKEDigest(securityBytes == 16 ? 128 : 256);
        offEA = (8 * ffYBytes) - (isA ? 4 : 1) * eA;
        offEB = (8 * mirathMatrixFFBytesSize(k, 1)) - (isA ? 4 : 1) * k;
        nRowsBytes1 = mirathMatrixFFBytesSize(m, 1); // Bytes per column for M rows
        nRowsBytes2 = mirathMatrixFFBytesSize(r, 1); // Bytes per column for R rows
        if (isA)
        {
            onCol1 = 8 - ((8 * nRowsBytes1) - (4 * m));
            onCol2 = 8 - ((8 * nRowsBytes2) - (4 * r));
        }
        else
        {
            onCol1 = 8 - ((8 * nRowsBytes1) - m);
            onCol2 = 8 - ((8 * nRowsBytes2) - r);
        }
    }

    public void mirathMatrixExpandSeedSecretMatrix(byte[] S, byte[] C, byte[] seedSk)
    {
        prng.update(seedSk, 0, securityBytes);
        // Generate all bytes for S and C in one go
        byte[] T = new byte[S.length + C.length];
        prng.doFinal(T, 0, T.length);

        System.arraycopy(T, 0, S, 0, S.length);
        System.arraycopy(T, S.length, C, 0, C.length);

        mirathMatrixSetToFF(S, m, r);
        mirathMatrixSetToFF(C, r, m - r);
    }

    public void mirathMatrixExpandSeedPublicMatrix(byte[] H, byte[] seedPk, int seedPkOff)
    {
        prng.update(seedPk, seedPkOff, securityBytes);
        prng.doFinal(H, 0, ffHBytes);
        mirathMatrixSetToFF(H, eA, k);
    }

    public void mirathMatrixComputeY(byte[] y, byte[] S, byte[] C, byte[] H)
    {
        int eBSize = mirathMatrixFFBytesSize(k, 1);
        byte[] eA = new byte[ffYBytes];
        byte[] eB = new byte[eBSize];

        // Calculate intermediate matrices
        byte[] T = new byte[mirathMatrixFFBytesSize(m, m - r)];
        byte[] E = new byte[mirathMatrixFFBytesSize(m * m, 1)];

        matrixFFProduct(T, S, C, m, r, m - r);
        int nRows = m, nCols2 = m - r;
        ptr = 0;
        int offPtr = 8;

        int nRowsBytes = mirathMatrixFfBytesPerColumn(nRows);
        int onCol = 8 - ((8 * nRowsBytes) - ((isA ? 4 : 1) * nRows));

        offPtr = parse(E, S, offPtr, r, nRowsBytes, onCol);

        // Process matrix2
        col = 0;
        for (int j = 0; j < nCols2; j++)
        {
            parse(T, E, offPtr, nRowsBytes);

            if (offPtr <= onCol)
            {
                ptr++;
                if (offPtr < onCol)
                {
                    E[ptr] = (byte)((T[col] & 0xFF) >>> offPtr);
                }
            }
            col++;
            offPtr = (8 - ((onCol - offPtr) & 7));
        }

        // Process eA and eB
        System.arraycopy(E, 0, eA, 0, eA.length);
        if (offEA > 0)
        {
            byte mask = (byte)((1 << (8 - offEA)) - 1);
            eA[ffYBytes - 1] = (byte)(E[ffYBytes - 1] & mask);

            for (int i = 0; i < eBSize - 1; i++)
            {
                byte part1 = (byte)((E[ffYBytes - 1 + i] & 0xFF) >>> (8 - offEA));
                byte part2 = (byte)((E[ffYBytes + i] & 0xFF) << offEA);
                eB[i] = (byte)(part1 ^ part2);
            }

            if ((offEA + offEB) >= 8)
            {
                eB[eBSize - 1] = (byte)((E[E.length - 1] & 0xFF) >>> (8 - offEA));
            }
            else
            {
                byte part1 = (byte)((E[E.length - 2] & 0xFF) >>> (8 - offEA));
                byte part2 = (byte)((E[E.length - 1] & 0xFF) << offEA);
                eB[eBSize - 1] = (byte)(part1 ^ part2);
            }
        }
        else
        {
            System.arraycopy(E, ffYBytes, eB, 0, eBSize);
        }

        // Compute final y
        matrixFFProduct(y, H, eB, this.eA, k, 1);
        Bytes.xorTo(y.length, eA, y);
    }

    void parse(byte[] input, byte[] output, int offPtr, int nRowsBytes)
    {
        output[ptr] |= (input[col] << (8 - offPtr));
        for (int i = 0; i < nRowsBytes - 1; i++)
        {
            output[++ptr] = (byte)((input[col++] & 0xFF) >>> offPtr);
            output[ptr] |= (byte)((input[col] & 0xff) << (8 - offPtr));
        }
    }

    int parse(byte[] output, byte[] input, int offPtr, int numColumns, int nRowsBytes, int onCol)
    {
        for (int j = 0; j < numColumns; j++)
        {
            parse(input, output, offPtr, nRowsBytes);
            if (offPtr <= onCol)
            {
                output[++ptr] = (byte)((input[col] & 0xff) >>> offPtr);
            }
            offPtr = 8 - ((onCol - offPtr) & 7);
            col++;
        }
        return offPtr;
    }

    byte mirathMatrixFFGetEntry(byte[] matrix, int nRows, int i, int j)
    {
        if (isA)
        {
            int pos = j * ((nRows + 1) >>> 1) + (i >>> 1);
            return (byte)((i & 1) != 0 ? (matrix[pos] >>> 4) & 0x0F : matrix[pos] & 0x0F);
        }
        else
        {
            return (byte)((matrix[((nRows + 7) >>> 3) * j + (i >>> 3)] >>> (i & 7)) & 0x01);
        }
    }

    private byte mirathMatrixFFGetEntry(byte[] matrix, int off, int nRows, int i, int j)
    {
        if (isA)
        {
            int pos = j * ((nRows + 1) >>> 1) + (i >>> 1) + off;
            return (byte)((i & 1) != 0 ? (matrix[pos] >>> 4) & 0x0F : matrix[pos] & 0x0F);
        }
        else
        {
            return (byte)((matrix[off + ((nRows + 7) >>> 3) * j + (i >>> 3)] >>> (i & 7)) & 0x01);
        }
    }

    private void setMatrixEntry(byte[] matrix, int nRows, int i, int j, byte value)
    {
        if (isA)
        {
            int pos = j * ((nRows + 1) >>> 1) + (i >>> 1);
            if ((i & 1) != 0)
            {
                matrix[pos] = (byte)((matrix[pos] & 0x0F) | ((value & 0x0F) << 4));
            }
            else
            {
                matrix[pos] = (byte)((matrix[pos] & 0xF0) | (value & 0x0F));
            }
        }
        else
        {
            int bytesPerCol = (nRows + 7) >>> 3;
            int idxLine = i >>> 3;
            int bitLine = i & 7;
            byte mask = (byte)(0xff ^ (1 << bitLine));
            matrix[bytesPerCol * j + idxLine] = (byte)((matrix[bytesPerCol * j + idxLine] & mask) ^ (value << bitLine));
        }
    }

    void mirathMatrixSetToFF(byte[] matrix, int nRows, int nCols)
    {
        if (isA)
        {
            if ((nRows & 1) != 0)
            {
                mirathMatrixSetToFF(matrix, nRows, nCols, (byte)0x0F);
            }
        }
        else
        {
            if ((nRows & 7) != 0)
            {
                mirathMatrixSetToFF(matrix, nRows, nCols, (byte)(0xff >>> (8 - (nRows & 7))));
            }
        }
    }

    void mirathMatrixSetToFF(byte[] matrix, int off, int nRows, int nCols)
    {
        if (isA)
        {
            if ((nRows & 1) != 0)
            {
                mirathMatrixSetToFF(matrix, off, nRows, nCols, (byte)0x0F);
            }
        }
        else
        {
            if ((nRows & 7) != 0)
            {
                mirathMatrixSetToFF(matrix, off, nRows, nCols, (byte)(0xff >>> (8 - (nRows & 7))));
            }
        }
    }

    private void mirathMatrixSetToFF(byte[] matrix, int nRows, int nCols, byte mask)
    {
        int matrixHeight = mirathMatrixFfBytesPerColumn(nRows);
        int matrixHeightX = matrixHeight - 1;
        for (int i = 0; i < nCols; i++)
        {
            matrix[i * matrixHeight + matrixHeightX] &= mask;
        }
    }

    private void mirathMatrixSetToFF(byte[] matrix, int off, int nRows, int nCols, byte mask)
    {
        int matrixHeight = mirathMatrixFfBytesPerColumn(nRows);
        int matrixHeightX = matrixHeight - 1 + off;
        for (int i = 0; i < nCols; i++)
        {
            matrix[i * matrixHeight + matrixHeightX] &= mask;
        }
    }

    private int mirathMatrixFfBytesPerColumn(int nRows)
    {
        if (isA)
        {
            return (nRows + 1) >>> 1;
        }
        else
        {
            return (nRows + 7) >>> 3;
        }
    }

    int mirathMatrixFFBytesSize(int nRows, int nCols)
    {
        return nCols * mirathMatrixFfBytesPerColumn(nRows);
    }

    void mirathGGMTreeGetLeaves(byte[][] output, byte[][] tree)
    {
        int firstLeaf = treeLeaves - 1;
        for (int i = firstLeaf; i < tree.length; i++)
        {
            System.arraycopy(tree[i], 0, output[i - firstLeaf], 0, securityBytes);
        }
    }

    int mirathTcithPsi(int i, int e)
    {
        return i * tau + e;
    }

    void mirathTcithCommit(SHA3Digest digest, byte[] commit, byte[] salt, int e, int i, byte[] seed)
    {
        // Initialize hash with domain separator
        digest.update(domainSeparatorCmt);

        // Update with salt
        digest.update(salt, 0, saltBytes);

        // Update with index i (big-endian 4 bytes)
        byte[] iBytes = Pack.longToLittleEndian(mirathTcithPsi(i, e));
        digest.update(iBytes, 0, 4);

        // Update with seed
        digest.update(seed, 0, securityBytes);
        digest.doFinal(commit, 0);
    }

    byte mirathFFMuMult(byte a, byte b)
    {
        int idx = (b & 0xff) << 3;
        byte tmp = 0;
        // Check each bit in 'a' and accumulate results
        tmp ^= (a & 0x01) != 0 ? MIRATH_FF_MU_MULT_BASE[idx] : 0;
        tmp ^= (a & 0x02) != 0 ? MIRATH_FF_MU_MULT_BASE[idx + 1] : 0;
        tmp ^= (a & 0x04) != 0 ? MIRATH_FF_MU_MULT_BASE[idx + 2] : 0;
        tmp ^= (a & 0x08) != 0 ? MIRATH_FF_MU_MULT_BASE[idx + 3] : 0;
        tmp ^= (a & 0x10) != 0 ? MIRATH_FF_MU_MULT_BASE[idx + 4] : 0;
        tmp ^= (a & 0x20) != 0 ? MIRATH_FF_MU_MULT_BASE[idx + 5] : 0;
        tmp ^= (a & 0x40) != 0 ? MIRATH_FF_MU_MULT_BASE[idx + 6] : 0;
        tmp ^= (a & 0x80) != 0 ? MIRATH_FF_MU_MULT_BASE[idx + 7] : 0;
        return tmp;
    }

    public short mirathFFMuMult(short a, short b)
    {
        if (isA)
        {
            // Extract 4-bit limbs from 12-bit values (stored in 16-bit space)
            int a0 = a & 0xF;
            int a1 = (a >>> 4) & 0xF;
            int a2 = (a >>> 8) & 0xF;

            int b0 = b & 0xF;
            int b1 = (b >>> 4) & 0xF;
            int b2 = (b >>> 8) & 0xF;

            // Compute basic products
            int p0 = GF16.mul(a0, b0);
            int p1 = GF16.mul(a1, b1);
            int p2 = GF16.mul(a2, b2);

            // Compute intermediate sums
            int a01 = a0 ^ a1;
            int a12 = a1 ^ a2;
            int a02 = a0 ^ a2;
            int b01 = b0 ^ b1;
            int b12 = b1 ^ b2;
            int b02 = b0 ^ b2;

            // Compute cross products
            int p01 = GF16.mul(a01, b01);
            int p12 = GF16.mul(a12, b12);
            int p02 = GF16.mul(a02, b02);

            // Combine terms
            int r = p1 ^ p2 ^ p12 ^ p0;

            // Apply shifts and combine
            r ^= (p0 << 4);
            r ^= (p01 << 4);
            r ^= (p12 << 4);
            r ^= (p02 << 8);
            r ^= (p0 << 8);
            r ^= (p1 << 8);

            // Mask to 16 bits (12 significant bits)
            return (short)(r & 0xFFFF);
        }
        else
        {
            short result = (short)(-(a & 1) & b);
            short tmp = b;
            for (int i = 1; i < 12; ++i)
            {
                tmp = (short)((tmp << 1) ^ (-(tmp >>> 11) & 0x1009));
                result ^= (-(a >>> i & 1) & tmp);
            }
            return result;
        }
    }

    void parseV(byte[] sample, short[] v_rnd)
    {
        Pack.littleEndianToShort(sample, ffSBytes + ffCBytes, v_rnd, 0, rho >>> 1);
        if ((rho & 1) != 0)
        {
            v_rnd[rho >>> 1] = (short)(sample[ffSBytes + ffCBytes + rho - 1] & 0xff);
        }

        for (int j = 0; j < rho; ++j)
        {
            // this works only for (q=2, mu=12) and (q=16, mu=3)
            v_rnd[j] &= 0x0FFF;
        }
    }

    void cipherInit(BlockCipher cipher, byte[] seed)
    {
        byte[] keyBytes;
        if (securityBytes == 16)
        {
            keyBytes = new byte[securityBytes];
        }
        else
        {
            keyBytes = new byte[32];
        }
        System.arraycopy(seed, 0, keyBytes, 0, securityBytes);
        cipher.init(true, new KeyParameter(keyBytes));
    }

    void mirathExpandSeed(BlockCipher cipher, byte[][] pairNode, int pos, byte[] salt, int idx, byte[] seed)
    {
        cipherInit(cipher, seed);
        byte[] msg = new byte[securityBytes == 16 ? 16 : 32];
        System.arraycopy(salt, 0, msg, 0, securityBytes);
        byte[] bytes = Pack.intToLittleEndian(idx);
        Bytes.xorTo(4, bytes, 0, msg, 1);
        msg[5] ^= domainSeparatorPrg;
        if (securityBytes == 24)
        {
            byte[] output = new byte[32];
            cipher.processBlock(msg, 0, output, 0);
            System.arraycopy(output, 0, pairNode[pos], 0, securityBytes);

            msg[0] ^= 0x01;
            Arrays.clear(output);
            cipher.processBlock(msg, 0, output, 0);
            System.arraycopy(output, 0, pairNode[pos + 1], 0, securityBytes);
        }
        else
        {
            cipher.processBlock(msg, 0, pairNode[pos], 0);
            msg[0] ^= 0x01;
            cipher.processBlock(msg, 0, pairNode[pos + 1], 0);
        }
    }

    public void mirathMatrixFFMuAddMultipleFF(byte[] matrix, byte scalar, byte[] src, int nRows, int nCols)
    {
        if (isA)
        {
            for (int i = 0; i < nRows; i++)
            {
                for (int j = 0; j < nCols; j++)
                {
                    int pos = j * ((nRows + 1) >>> 1) + (i >>> 1);
                    byte entry = (byte)((i & 1) != 0 ? (src[pos] >>> 4) & 0x0F : src[pos] & 0x0F);
                    matrix[j * nRows + i] ^= mirathFFMuMult(scalar, MIRATH_MAP_FF_TO_FF_MU[entry]);
                }
            }
        }
        else
        {
            for (int i = 0; i < nRows; i++)
            {
                for (int j = 0; j < nCols; j++)
                {
                    matrix[j * nRows + i] ^= mirathFFMuMult(scalar, (byte)((src[((nRows + 7) >>> 3) * j + (i >>> 3)] >>> (i & 7)) & 0x01));
                }
            }
        }
    }

    public void mirathMatrixFFMuAddMultipleFF(byte[] matrix, byte scalar, byte[] src, int off, int nRows, int nCols)
    {
        if (isA)
        {
            for (int i = 0; i < nRows; i++)
            {
                for (int j = 0; j < nCols; j++)
                {
                    int pos = j * ((nRows + 1) >>> 1) + (i >>> 1) + off;
                    matrix[j * nRows + i] ^= mirathFFMuMult(scalar, MIRATH_MAP_FF_TO_FF_MU[((i & 1) != 0 ? (src[pos] >>> 4) & 0x0F : src[pos] & 0x0F)]);
                }
            }
        }
        else
        {
            for (int i = 0; i < nRows; i++)
            {
                for (int j = 0; j < nCols; j++)
                {
                    matrix[j * nRows + i] ^= mirathFFMuMult(scalar, (byte)((src[off + ((nRows + 7) >>> 3) * j + (i >>> 3)] >>> (i & 7)) & 0x01));
                }
            }
        }
    }

    void matrixFFMuAddMu1FFTo(byte[] matrix1, byte[] matrix3, int rows, int cols)
    {
        if (isA)
        {
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    int pos = j * ((rows + 1) >>> 1) + (i >>> 1);
                    byte entry = (byte)((i & 1) != 0 ? (matrix3[pos] >>> 4) & 0x0F : matrix3[pos] & 0x0F);
                    matrix1[j * rows + i] ^= MIRATH_MAP_FF_TO_FF_MU[entry];
                }
            }
        }
        else
        {
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    matrix1[j * rows + i] ^= (byte)((matrix3[((rows + 7) >>> 3) * j + (i >>> 3)] >>> (i & 7)) & 0x01);
                }
            }
        }
    }

    void matrixFFMuAddMu1FFTo(short[] matrix1, byte[] matrix3, int rows, int cols)
    {
        if (isA)
        {
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    int pos = j * ((rows + 1) >>> 1) + (i >>> 1);
                    matrix1[j * rows + i] ^= ((i & 1) != 0 ? (matrix3[pos] >>> 4) & 0x0F : matrix3[pos] & 0x0F);
                }
            }
        }
        else
        {
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    matrix1[j * rows + i] ^= ((matrix3[((rows + 7) >>> 3) * j + (i >>> 3)] >>> (i & 7)) & 0x01);
                }
            }
        }
    }

    public void mirathMatrixFFMuAddMultipleFF(short[] matrix, short scalar, byte[] src)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < r; j++)
            {
                matrix[m * j + i] ^= mirathFFMuMult(scalar, mirathMatrixFFGetEntry(src, m, i, j));
            }
        }
    }

    public void mirathMatrixFFMuAddMultipleFF(short[] matrix, short scalar, byte[] src, int off)
    {
        for (int i = 0; i < r; i++)
        {
            for (int j = 0; j < m - r; j++)
            {
                matrix[r * j + i] ^= mirathFFMuMult(scalar, mirathMatrixFFGetEntry(src, off, r, i, j));
            }
        }
    }

    /**
     * Performs vector1 = vector2 + scalar * vector3 in GF(2^8)
     *
     * @param vector1 Destination vector (modified in-place)
     * @param scalar  Scalar multiplier
     * @param vector3 Second operand vector
     * @param ncols   Number of elements to process
     */
    public void mirathVectorFFMuAddMultiple(byte[] vector1, byte scalar, byte[] vector3, int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            // GF(2^8) multiplication followed by addition (XOR)
            vector1[i] ^= mirathFFMuMult(scalar, vector3[i]);
        }
    }

    public void mirathVectorFFMuAddMultiple(byte[] vector1, byte scalar, byte[] vector3, int off, int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            // GF(2^8) multiplication followed by addition (XOR)
            vector1[i] ^= mirathFFMuMult(scalar, vector3[off + i]);
        }
    }

    public void mirathVectorFFMuAddMultiple(short[] vector1, short scalar, short[] vector3, int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            // GF(2^8) multiplication followed by addition (XOR)
            vector1[i] ^= mirathFFMuMult(scalar, vector3[i]);
        }
    }

    public void mirathVectorFFMuAddMultipleFF(byte[] vector1, byte scalar, byte[] vector3, int ncols)
    {
        if (isA)
        {
            for (int i = 0; i < ncols; i++)
            {
                vector1[i] ^= mirathFFMuMult(scalar, MIRATH_MAP_FF_TO_FF_MU[((i & 1) != 0 ? (vector3[i >>> 1] >>> 4) & 0x0F : vector3[i >>> 1] & 0x0F)]);
            }
        }
        else
        {
            for (int i = 0; i < ncols; i++)
            {
                vector1[i] ^= mirathFFMuMult(scalar, MIRATH_MAP_FF_TO_FF_MU[((vector3[(i >>> 3)] >>> (i & 7)) & 0x01)]);
            }
        }
    }

    public void mirathVectorFFMuAddMultipleFF(short[] vector1, short scalar, byte[] vector3, int ncols)
    {
        if (isA)
        {
            for (int i = 0; i < ncols; i++)
            {
                vector1[i] ^= mirathFFMuMult(scalar, (short)((i & 1) != 0 ? (vector3[i >>> 1] >>> 4) & 0x0F : vector3[i >>> 1] & 0x0F));
            }
        }
        else
        {
            for (int i = 0; i < ncols; i++)
            {
                vector1[i] ^= mirathFFMuMult(scalar, (short)((vector3[(i >>> 3)] >>> (i & 7)) & 0x01));
            }
        }
    }


    public void matrixFFProduct(byte[] result, byte[] matrix1, byte[] matrix2, int nRows1, int nCols1, int nCols2)
    {
        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0; j < nCols2; j++)
            {
                byte entry_i_j = 0;
                for (int k = 0; k < nCols1; k++)
                {
                    byte entry_i_k = mirathMatrixFFGetEntry(matrix1, nRows1, i, k);
                    byte entry_k_j = mirathMatrixFFGetEntry(matrix2, nCols1, k, j);
                    entry_i_j ^= GF16.mul(entry_i_k, entry_k_j);
                }
                setMatrixEntry(result, nRows1, i, j, entry_i_j);
            }
        }
    }

    public void matrixFFMuProduct(byte[] result, int off, byte[] matrix1, byte[] matrix2, int nRows1, int nCols1, int nCols2)
    {
        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0; j < nCols2; j++)
            {
                result[nRows1 * j + i + off] = getEntry_i_j(matrix1, matrix2, nRows1, nCols1, i, j);
            }
        }
    }

    private byte getEntry_i_j(byte[] matrix1, byte[] matrix2, int nRows1, int nCols1, int i, int j)
    {
        byte entry_i_j = 0;
        for (int k = 0; k < nCols1; k++)
        {
            byte entry_i_k = matrix1[nRows1 * k + i];
            byte entry_k_j = matrix2[nCols1 * j + k];
            entry_i_j ^= mirathFFMuMult(entry_i_k, entry_k_j);
        }
        return entry_i_j;
    }

    public void matrixFFMuProductTo(byte[] result, byte[] matrix1, byte[] matrix2)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < m - r; j++)
            {
                byte entry_i_j = getEntry_i_j(matrix1, matrix2, m, r, i, j);
                result[j * m + i] ^= entry_i_j;
            }
        }
    }

    public void  matrixFFMuProductXor(byte[] result, byte[] matrix1, byte[] matrix2, byte[] matrix3)
    {
        for (int i = 0; i < rho; i++)
        {
            byte entry_i_j = matrix3[i];
            for (int k = 0; k < eA; k++)
            {
                entry_i_j ^= mirathFFMuMult(matrix1[rho * k + i], matrix2[k]);
            }
            result[i] = entry_i_j;
        }
    }

    public void matrixFFMuProduct(short[] result, int off, short[] matrix1, short[] matrix2, int nRows1, int nCols1, int nCols2)
    {
        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0; j < nCols2; j++)
            {
                result[j * nRows1 + i + off] = getEntry_i_j(matrix1, matrix2, nRows1, nCols1, i, j);
            }
        }
    }

    public void matrixFFMuProductTo(short[] result, short[] matrix1, short[] matrix2)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < m - r; j++)
            {
                result[j * m + i] ^= getEntry_i_j(matrix1, matrix2, m, r, i, j);
            }
        }
    }

    private short getEntry_i_j(short[] matrix1, short[] matrix2, int nRows1, int nCols1, int i, int j)
    {
        short entry_i_j = 0;
        for (int k = 0; k < nCols1; k++)
        {
            short entry_i_k = matrix1[nRows1 * k + i];
            short entry_k_j = matrix2[nCols1 * j + k];
            entry_i_j ^= mirathFFMuMult(entry_i_k, entry_k_j);
        }
        return entry_i_j;
    }

    public void matrixFFMuProductXor(short[] result, short[] matrix1, short[] matrix2, short[] matrix3)
    {
        for (int i = 0; i < rho; i++)
        {
            short entry_i_j = matrix3[i];
            for (int k = 0; k < eA; k++)
            {
                entry_i_j ^= mirathFFMuMult(matrix1[rho * k + i], matrix2[k]);
            }
            result[i] = entry_i_j;
        }
    }

    void matrixFFMuProductFF1MuTo(byte[] result, byte[] mat1, int rows1, int cols1)
    {
        if (isA)
        {
            for (int i = 0; i < rows1; i++)
            {
                byte entry_i_j = 0;
                for (int k = 0; k < cols1; k++)
                {
                    int pos = k * ((rows1 + 1) >>> 1) + (i >>> 1);
                    byte entry_i_k = MIRATH_MAP_FF_TO_FF_MU[((i & 1) != 0 ? (mat1[pos] >>> 4) & 0x0F : mat1[pos] & 0x0F)];
                    entry_i_j ^= mirathFFMuMult(entry_i_k, result[rows1 + k]);
                }
                result[i] ^= entry_i_j;
            }
        }
        else
        {
            for (int i = 0; i < rows1; i++)
            {
                byte entry_i_j = 0;
                for (int k = 0; k < cols1; k++)
                {
                    byte entry_i_k = (byte)((mat1[((rows1 + 7) >>> 3) * k + (i >>> 3)] >>> (i & 7)) & 0x01);
                    entry_i_j ^= mirathFFMuMult(entry_i_k, result[rows1 + k]);
                }
                result[i] ^= entry_i_j;
            }
        }
    }

    void matrixFFMuProductFF1MuTo(short[] result, byte[] mat1, int rows1, int cols1)
    {
        if (isA)
        {
            for (int i = 0; i < rows1; i++)
            {
                short entry_i_j = 0;
                for (int k = 0; k < cols1; k++)
                {
                    int pos = k * ((rows1 + 1) >>> 1) + (i >>> 1);
                    short entry_i_k = (short)((i & 1) != 0 ? (mat1[pos] >>> 4) & 0x0F : mat1[pos] & 0x0F);
                    short entry_k_j = result[rows1 + k];
                    entry_i_j ^= mirathFFMuMult(entry_i_k, entry_k_j);
                }
                result[i] ^= entry_i_j;
            }
        }
        else
        {
            for (int i = 0; i < rows1; i++)
            {
                short entry_i_j = 0;
                for (int k = 0; k < cols1; k++)
                {
                    entry_i_j ^= mirathFFMuMult((short)((mat1[((rows1 + 7) >>> 3) * k + (i >>> 3)] >>> (i & 7)) & 0x01),
                        result[rows1 + k]);
                }
                result[i] ^= entry_i_j;
            }
        }
    }

    void matrixFFMuAddMu1FF(byte[] matrix1, byte[] matrix2, byte[] matrix3, int rows, int cols)
    {
        if (isA)
        {
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    int pos = j * ((rows + 1) >>> 1) + (i >>> 1);
                    byte entry1 = matrix2[rows * j + i];
                    byte entry2 = MIRATH_MAP_FF_TO_FF_MU[((i & 1) != 0 ? (matrix3[pos] >>> 4) & 0x0F : matrix3[pos] & 0x0F)];
                    matrix1[rows * j + i] = (byte)(entry1 ^ entry2);
                }
            }
        }
        else
        {
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    byte entry1 = matrix2[rows * j + i];
                    byte entry2 = (byte)((matrix3[((rows + 7) >>> 3) * j + (i >>> 3)] >>> (i & 7)) & 0x01);
                    matrix1[rows * j + i] = (byte)(entry1 ^ entry2);
                }
            }
        }
    }

    void matrixFFMuAddMu1FF(short[] matrix1, short[] matrix2, byte[] matrix3, int rows, int cols)
    {
        if (isA)
        {
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    int pos = j * ((rows + 1) >>> 1) + (i >>> 1);
                    short entry1 = matrix2[rows * j + i];
                    short entry2 = (short)((i & 1) != 0 ? (matrix3[pos] >>> 4) & 0x0F : matrix3[pos] & 0x0F);
                    matrix1[rows * j + i] = (short)(entry1 ^ entry2);
                }
            }
        }
        else
        {
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    short entry1 = matrix2[rows * j + i];
                    short entry2 = (short)((matrix3[((rows + 7) >>> 3) * j + (i >>> 3)] >>> (i & 7)) & 0x01);
                    matrix1[rows * j + i] = (short)(entry1 ^ entry2);
                }
            }
        }
    }

    public byte multivcOpen(byte[][] path, byte[][] commitsIStar, byte[][] tree, byte[][][] commits, int[] iStar)
    {
        int[] pathIndexes = new int[maxOpen];
        int pathLength = getPathIndexes(iStar, pathIndexes);

        // Copy the seeds from the tree to the path
        for (int i = 0; i < pathLength; i++)
        {
            int index = pathIndexes[i];
            System.arraycopy(tree[index], 0, path[i], 0, securityBytes);
        }

        if (pathLength > tOpen)
        {
            for (byte[] arr : path)
            {
                Arrays.fill(arr, (byte)0);
            }
            return 1;
        }

        for (int e = 0; e < tau; e++)
        {
            System.arraycopy(commits[e][iStar[e]], 0, commitsIStar[e], 0, 2 * securityBytes);
        }
        return 0;
    }

    private int getPathIndexes(int[] iStar, int[] pathIndexes)
    {
        int[] psiIStar = new int[tau];

        for (int e = 0; e < tau; e++)
        {
            psiIStar[e] = mirathTcithPsi(iStar[e], e);
        }
//        int pathLength = 0;

        //Build path index list
//        for (int leaf : psiIStar)
//        {
//            int node = leavesSeedsOffset + leaf;
//            while (node > 0)
//            {
//                int pos = isInList(pathIndexes, pathLength, node);
//                if (pos >= 0)
//                {
//                    pathLength = removeFromList(pathIndexes, pathLength, pos);
//                    break;
//                }
//                else
//                {
//                    int sibling = (node & 1) == 1 ? node + 1 : node - 1;
//                    int prevN = pathLength;
//                    pathLength = insertSorted(pathIndexes, pathLength, sibling, maxOpen);
//                    if (prevN == pathLength)
//                    {
//                        return -1;
//                    }
//                }
//                node = getParent(node);
//            }
//        }
//        return pathLength;
        List<Integer> pathIndexes1 = new ArrayList<>();

        for (int leaf : psiIStar)
        {
            int node = leavesSeedsOffset + leaf;
            while (node > 0)
            {
                int pos = Collections.binarySearch(pathIndexes1, node);
                if (pos >= 0)
                {
                    pathIndexes1.remove(pos);
                    break;
                }
                else
                {
                    int sibling = (node & 1) == 1 ? node + 1 : node - 1;
                    if (pathIndexes1.size() >= maxOpen)
                    {
                        return -1;
                    }
                    int insertPos = -pos - 1;
                    pathIndexes1.add(insertPos, sibling);
                }
                node = getParent(node);
            }
        }
        for (int i = 0; i < pathIndexes1.size(); i++)
        {
            pathIndexes[i] = pathIndexes1.get(i);  // auto‑unboxing from Integer to int
        }
        return pathIndexes1.size();
    }

    private static int getParent(int nodeIndex)
    {
        return (nodeIndex - 1) / 2;
    }

    int multivcReconstruct(SHA3Digest hash, SHA3Digest digest, BlockCipher cipher, byte[] hCom, byte[][] seeds,
                           int[] iStar, byte[][] path, byte[][] commitsIStar, byte[] salt, byte[][] tree, byte[][][] commits)
    {
        int[] pathIndexes = new int[maxOpen];
        int n = getPathIndexes(iStar, pathIndexes);

        int pathLength = 0;
        final byte[] zeroArray = new byte[securityBytes]; // Automatically initialized to all zeros

        for (int i = 0; i < tOpen; i++)
        {
            if (!Arrays.areEqual(path[i], zeroArray))
            {
                pathLength++;
            }
        }

        // Process tree nodes
        int k = 0;
        int parentNode = k < n ? getParent(pathIndexes[k]) : -1;
        boolean[] valid = new boolean[treeLeaves + 1];

        for (int i = 0; i < treeLeaves - 1; i++)
        {
            if (i == parentNode)
            {
                System.arraycopy(path[k], 0, tree[pathIndexes[k]], 0, securityBytes);
                if (i < treeLeaves / 2)
                {
                    valid[pathIndexes[k]] = true;
                }
                k++;
                if (k < pathLength)
                {
                    parentNode = getParent(pathIndexes[k]);
                }
            }
            else
            {
                if (valid[i])
                {
                    int child0 = 2 * i + 1;
                    mirathExpandSeed(cipher, tree, child0, salt, i, tree[i]);
                    if (i < treeLeaves / 2)
                    {
                        valid[child0] = true;
                        valid[child0 + 1] = true;
                    }
                }
            }
        }

        if (k != pathLength)
        {
            return -1;
        }

        mirathGGMTreeGetLeaves(seeds, tree);

        hash.update(domainSeparatorCommitment);
        // Process commits
        for (int e = 0; e < tau; e++)
        {
            System.arraycopy(commitsIStar[e], 0, commits[e][iStar[e]], 0, 2 * securityBytes);
            for (int i = 0; i < n1; i++)
            {
                if (i != iStar[e])
                {
                    mirathTcithCommit(digest, commits[e][i], salt, e, i, seeds[mirathTcithPsi(i, e)]);
                }
                hash.update(commits[e][i], 0, 2 * securityBytes);
            }
        }

        hash.doFinal(hCom, 0);

        return 0;
    }

    private static int isInList(int[] arr, int n, int x)
    {
        int left = 0;
        int right = n - 1;

        while (left <= right)
        {
            int mid = left + (right - left) / 2;
            if (arr[mid] == x)
            {
                return mid;
            }
            if (arr[mid] < x)
            {
                left = mid + 1;
            }
            else
            {
                right = mid - 1;
            }
        }
        return -1;
    }

    private static int removeFromList(int[] arr, int n, int pos)
    {
        if (pos >= n)
        {
            return n;
        }
        System.arraycopy(arr, pos + 1, arr, pos, n - pos - 1);
        return n - 1;
    }

    private static int insertSorted(int[] arr, int n, int key, int capacity)
    {
        if (n >= capacity)
        {
            return n;
        }
        int i = n - 1;
        while (i >= 0 && arr[i] > key)
        {
            arr[i + 1] = arr[i];
            i--;
        }
        arr[i + 1] = key;
        return n + 1;
    }

    public void mirathMatrixFFMuAddMultiple2(byte[] matrix, byte scalar, byte[] src)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < r; j++)
            {
                matrix[m * j + i] = mirathFFMuMult(scalar, src[m * j + i]);
            }
        }
    }

    public void mirathMatrixFFMuAddMultiple2(short[] matrix, short scalar, short[] src)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < r; j++)
            {
                matrix[m * j + i] = mirathFFMuMult(scalar, src[m * j + i]);
            }
        }
    }
}
