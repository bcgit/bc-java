package org.bouncycastle.pqc.crypto.mirath;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class MirathEngine
{
    public final int securityBytes;
    public final int saltBytes;
    public final int m;
    public final int r;
    public final int n;
    private final int n2;
    private final int n1;
    public final int k;
    private final int tau;
    public final int tau1;
    public final int tau2;
    private final int rho;
    private final boolean isA;
    public final int ffYBytes;
    private final int offEA;
    private final int offEB;
    private final int treeLeaves;
    private final int blockLength;
    private static final int domainSeparatorCommitment = 5;
    private static final int domainSeparatorPrg = 4;
    private static final int domainSeparatorHash1 = 1;
    // GF(16) multiplication table (replace with actual implementation if different)
    private static final byte[] MIRATH_FF_MULT_TABLE = new byte[]{
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
        (byte)0x00, (byte)0x02, (byte)0x04, (byte)0x06, (byte)0x08, (byte)0x0a, (byte)0x0c, (byte)0x0e, (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x05, (byte)0x0b, (byte)0x09, (byte)0x0f, (byte)0x0d,
        (byte)0x00, (byte)0x03, (byte)0x06, (byte)0x05, (byte)0x0c, (byte)0x0f, (byte)0x0a, (byte)0x09, (byte)0x0b, (byte)0x08, (byte)0x0d, (byte)0x0e, (byte)0x07, (byte)0x04, (byte)0x01, (byte)0x02,
        (byte)0x00, (byte)0x04, (byte)0x08, (byte)0x0c, (byte)0x03, (byte)0x07, (byte)0x0b, (byte)0x0f, (byte)0x06, (byte)0x02, (byte)0x0e, (byte)0x0a, (byte)0x05, (byte)0x01, (byte)0x0d, (byte)0x09,
        (byte)0x00, (byte)0x05, (byte)0x0a, (byte)0x0f, (byte)0x07, (byte)0x02, (byte)0x0d, (byte)0x08, (byte)0x0e, (byte)0x0b, (byte)0x04, (byte)0x01, (byte)0x09, (byte)0x0c, (byte)0x03, (byte)0x06,
        (byte)0x00, (byte)0x06, (byte)0x0c, (byte)0x0a, (byte)0x0b, (byte)0x0d, (byte)0x07, (byte)0x01, (byte)0x05, (byte)0x03, (byte)0x09, (byte)0x0f, (byte)0x0e, (byte)0x08, (byte)0x02, (byte)0x04,
        (byte)0x00, (byte)0x07, (byte)0x0e, (byte)0x09, (byte)0x0f, (byte)0x08, (byte)0x01, (byte)0x06, (byte)0x0d, (byte)0x0a, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x05, (byte)0x0c, (byte)0x0b,
        (byte)0x00, (byte)0x08, (byte)0x03, (byte)0x0b, (byte)0x06, (byte)0x0e, (byte)0x05, (byte)0x0d, (byte)0x0c, (byte)0x04, (byte)0x0f, (byte)0x07, (byte)0x0a, (byte)0x02, (byte)0x09, (byte)0x01,
        (byte)0x00, (byte)0x09, (byte)0x01, (byte)0x08, (byte)0x02, (byte)0x0b, (byte)0x03, (byte)0x0a, (byte)0x04, (byte)0x0d, (byte)0x05, (byte)0x0c, (byte)0x06, (byte)0x0f, (byte)0x07, (byte)0x0e,
        (byte)0x00, (byte)0x0a, (byte)0x07, (byte)0x0d, (byte)0x0e, (byte)0x04, (byte)0x09, (byte)0x03, (byte)0x0f, (byte)0x05, (byte)0x08, (byte)0x02, (byte)0x01, (byte)0x0b, (byte)0x06, (byte)0x0c,
        (byte)0x00, (byte)0x0b, (byte)0x05, (byte)0x0e, (byte)0x0a, (byte)0x01, (byte)0x0f, (byte)0x04, (byte)0x07, (byte)0x0c, (byte)0x02, (byte)0x09, (byte)0x0d, (byte)0x06, (byte)0x08, (byte)0x03,
        (byte)0x00, (byte)0x0c, (byte)0x0b, (byte)0x07, (byte)0x05, (byte)0x09, (byte)0x0e, (byte)0x02, (byte)0x0a, (byte)0x06, (byte)0x01, (byte)0x0d, (byte)0x0f, (byte)0x03, (byte)0x04, (byte)0x08,
        (byte)0x00, (byte)0x0d, (byte)0x09, (byte)0x04, (byte)0x01, (byte)0x0c, (byte)0x08, (byte)0x05, (byte)0x02, (byte)0x0f, (byte)0x0b, (byte)0x06, (byte)0x03, (byte)0x0e, (byte)0x0a, (byte)0x07,
        (byte)0x00, (byte)0x0e, (byte)0x0f, (byte)0x01, (byte)0x0d, (byte)0x03, (byte)0x02, (byte)0x0c, (byte)0x09, (byte)0x07, (byte)0x06, (byte)0x08, (byte)0x04, (byte)0x0a, (byte)0x0b, (byte)0x05,
        (byte)0x00, (byte)0x0f, (byte)0x0d, (byte)0x02, (byte)0x09, (byte)0x06, (byte)0x04, (byte)0x0b, (byte)0x01, (byte)0x0e, (byte)0x0c, (byte)0x03, (byte)0x08, (byte)0x07, (byte)0x05, (byte)0x0a,
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
        n = parameters.getN();
        n1 = parameters.getN1();
        n2 = parameters.getN2();
        rho = parameters.getRho();
        k = parameters.getK();
        isA = parameters.isA();
        tau = parameters.getTau();
        tau1 = parameters.getTau1();
        tau2 = parameters.getTau2();
        treeLeaves = parameters.getTreeLeaves();

        ffYBytes = calculateMatrixBytes(m * n - k, 1);
        blockLength = (ffYBytes + mirathMatrixFFBytesSize(r, n - r) + rho + (securityBytes - 1)) / securityBytes;

        offEA = (8 * ffYBytes) - (isA ? 4 : 1) * (m * n - k);
        offEB = (8 * calculateMatrixBytes(k, 1)) - (isA ? 4 : 1) * k;
    }

    public void mirathMatrixExpandSeedSecretMatrix(byte[] S, byte[] C, byte[] seedSk)
    {
        SHAKEDigest prng = new SHAKEDigest(securityBytes == 16 ? 128 : 256);
        mirathPrngInit(prng, null, seedSk, securityBytes);

        // Generate all bytes for S and C in one go
        byte[] T = new byte[S.length + C.length];
        prng.doFinal(T, 0, T.length);

        System.arraycopy(T, 0, S, 0, S.length);
        System.arraycopy(T, S.length, C, 0, C.length);

        mirathMatrixSetToFF(S, m, r);
        mirathMatrixSetToFF(C, r, n - r);
    }

    public void mirathMatrixExpandSeedPublicMatrix(byte[] H, byte[] seedPk)
    {
        SHAKEDigest prng = new SHAKEDigest(securityBytes == 16 ? 128 : 256);
        mirathPrngInit(prng, null, seedPk, securityBytes);

        int rows = m * m - k;
        int cols = k;
        int hBytes = calculateMatrixBytes(rows, cols);

        prng.doFinal(H, 0, hBytes);
        mirathMatrixSetToFF(H, rows, cols);
    }

    public void mirathMatrixComputeY(byte[] y, byte[] S, byte[] C, byte[] H)
    {
        int eASize = ffYBytes;
        int eBSize = calculateMatrixBytes(k, 1);
        byte[] eA = new byte[eASize];
        byte[] eB = new byte[eBSize];

        // Calculate intermediate matrices
        byte[] T = new byte[calculateMatrixBytes(m, n - r)];
        byte[] E = new byte[calculateMatrixBytes(m * n, 1)];

        matrixProduct(T, S, C, m, r, n - r);
        horizontalConcat(E, S, T, m, r, n - r);

        // Process eA and eB
        System.arraycopy(E, 0, eA, 0, eA.length);
        if (offEA > 0)
        {
            byte mask = (byte)((1 << (8 - offEA)) - 1);
            eA[eASize - 1] = (byte)(E[eASize - 1] & mask);

            for (int i = 0; i < eBSize - 1; i++)
            {
                byte part1 = (byte)((E[eASize - 1 + i] & 0xFF) >>> (8 - offEA));
                byte part2 = (byte)((E[eASize + i] & 0xFF) << offEA);
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
            System.arraycopy(E, eASize, eB, 0, eBSize);
        }

        // Compute final y
        Arrays.fill(y, (byte)0);
        matrixProduct(y, H, eB, m * n - k, k, 1);
        vectorAdd(y, y, eA);
    }

    private void matrixProduct(byte[] result, byte[] matrix1, byte[] matrix2,
                               int nRows1, int nCols1, int nCols2)
    {
//        int matrixHeight = mirathMatrixFfBytesPerColumn(nRows1);

        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0; j < nCols2; j++)
            {
                byte entry = 0;

                for (int k = 0; k < nCols1; k++)
                {
                    byte a = getMatrixEntry(matrix1, nRows1, i, k);
                    byte b = getMatrixEntry(matrix2, nCols1, k, j);
                    entry ^= ffMultiply(a, b);
                }

                setMatrixEntry(result, nRows1, i, j, entry);
            }
        }

//        if ((nRows1 & 1) != 0)
//        {
//            int matrixHeightX = matrixHeight - 1;
//            for (int i = 0; i < nCols2; i++)
//            {
//                result[i * matrixHeight + matrixHeightX] &= 0x0F;
//            }
//        }
    }

    private byte getMatrixEntry(byte[] matrix, int nRows, int i, int j)
    {
        int bytesPerCol = mirathMatrixFfBytesPerColumn(nRows);
        if (isA)
        {
            int pos = j * bytesPerCol + (i >>> 1);
            return (byte)((i & 1) != 0 ?
                (matrix[pos] & 0xFF) >>> 4 :
                matrix[pos] & 0x0F);
        }
        else
        {
            int idxLine = i >>> 3;
            int bitLine = i & 7;
            return (byte)((matrix[bytesPerCol * j + idxLine] >>> bitLine) & 0x01);
        }
    }

    private void setMatrixEntry(byte[] matrix, int nRows, int i, int j, byte value)
    {
        int bytesPerCol = mirathMatrixFfBytesPerColumn(nRows);
        int pos = j * bytesPerCol + (i >>> 1);
        if (isA)
        {
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
            int idxLine = i >>> 3;
            int bitLine = i & 7;
            byte mask = (byte)(0xff ^ (1 << bitLine));
            matrix[bytesPerCol * j + idxLine] = (byte)((matrix[bytesPerCol * j + idxLine] & mask) ^ (value << bitLine));
        }
    }

//    private void horizontalConcat(byte[] result, byte[] matrix1, byte[] matrix2,
//                                         int nRows, int nCols1, int nCols2)
//    {
//        int bytesPerCol = bytesPerColumn(nRows);
//        int onCol = 8 - ((8 * bytesPerCol) - (4 * nRows));
//
//        int ptr = 0;
//        int offPtr = 8;  // Tracks bits remaining in current byte (starts empty)
//
//        // Process matrix1 columns
//        for (int j = 0; j < nCols1; j++)
//        {
//            int colStart = j * bytesPerCol;
//            for (int i = 0; i < bytesPerCol; i++)
//            {
//                byte current = matrix1[colStart + i];
//
//                // Process upper nibble (4 bits)
//                byte nibble = (byte)((current & 0xF0) >>> 4);
//                processNibble(result, nibble, ref ptr, ref offPtr, onCol);
//
//                // Process lower nibble (4 bits) if not last byte or if there's space
//                if (i < bytesPerCol - 1 || (nRows % 2 == 0))
//                {
//                    nibble = (byte)(current & 0x0F);
//                    processNibble(result, nibble, ref ptr, ref offPtr, onCol);
//                }
//            }
//        }
//
//        // Process matrix2 columns
//        for (int j = 0; j < nCols2; j++)
//        {
//            int colStart = j * bytesPerCol;
//            for (int i = 0; i < bytesPerCol; i++)
//            {
//                byte current = matrix2[colStart + i];
//
//                // Process upper nibble
//                byte nibble = (byte)((current & 0xF0) >>> 4);
//                processNibble(result, nibble, ref ptr, ref offPtr, onCol);
//
//                // Process lower nibble
//                if (i < bytesPerCol - 1 || (nRows % 2 == 0))
//                {
//                    nibble = (byte)(current & 0x0F);
//                    processNibble(result, nibble, ref ptr, ref offPtr, onCol);
//                }
//            }
//        }
//    }

//    private void processNibble(byte[] result, byte nibble,
//                               int[] ptrHolder, int[] offPtrHolder, int onCol)
//    {
//        int ptr = ptrHolder[0];
//        int offPtr = offPtrHolder[0];
//
////        if (offPtr == 8)
////        {  // Start new byte
////            //result[ptr] = 0;
////            offPtr = 0;
////        }
//
//        // Calculate available space in current byte
//        int shift = 4 - offPtr;
//        if (shift >= 0)
//        {
//            // Fits in current byte
//            result[ptr] |= (byte)((nibble & 0x0F) << (4 - offPtr));
//            offPtr += 4;
//        }
//        else
//        {
//            // Split across bytes
//            result[ptr] |= (byte)((nibble & 0x0F) >>> (-shift));
//            ptr++;
//            result[ptr] = (byte)((nibble & 0x0F) << (8 + shift));
//            offPtr = 4 + shift;
//        }
//
//        // Check if byte is full
//        if (offPtr >= 8)
//        {
//            ptr++;
//            offPtr %= 8;
//        }
//
//        // Handle special column alignment
//        if (offPtr > onCol)
//        {
//            ptr++;
//            offPtr = 8 - (onCol - (offPtr - 8));
//        }
//
//        // Update holder arrays
//        ptrHolder[0] = ptr;
//        offPtrHolder[0] = offPtr;
//    }

    // Modified horizontalConcat caller
    private void horizontalConcat(byte[] result, byte[] matrix1, byte[] matrix2,
                                  int nRows, int nCols1, int nCols2)
    {
//        int bytesPerCol = mirathMatrixFfBytesPerColumn(nRows);
//        int onCol = 8 - ((8 * bytesPerCol) - ((isA ? 4 : 1) * nRows));
//
//        // Use arrays to simulate ref parameters
//        int[] ptrHolder = new int[1];
//        int[] offPtrHolder = new int[]{8};  //8// Start with empty byte
//
//        // Process matrix1
//        processColumns(result, matrix1, nCols1, bytesPerCol, nRows, ptrHolder, offPtrHolder, onCol);
//
//        // Process matrix2
//        processColumns(result, matrix2, nCols2, bytesPerCol, nRows, ptrHolder, offPtrHolder, onCol);
        int ptrIndex = 0;
        int offPtr = 8;

        int nRowsBytes = mirathMatrixFfBytesPerColumn(nRows);
        int onCol = 8 - ((8 * nRowsBytes) - ((isA ? 4 : 1) * nRows));

        int colIndex;

        // Process matrix1
        colIndex = 0;
        for (int j = 0; j < nCols1; j++)
        {
            result[ptrIndex] |= (matrix1[colIndex] << (8 - offPtr));

            for (int i = 0; i < nRowsBytes - 1; i++)
            {
                ptrIndex++;
                result[ptrIndex] = (byte)((matrix1[colIndex] & 0xFF) >>> offPtr);
                colIndex++;
                result[ptrIndex] |= (matrix1[colIndex] << (8 - offPtr));
            }

            if (offPtr <= onCol)
            {
                ptrIndex++;
                result[ptrIndex] = (byte)((matrix1[colIndex] & 0xFF) >>> offPtr);
            }
            colIndex++;
            offPtr = (8 - ((onCol - offPtr) % 8));
            if (offPtr > 8)
            {
                offPtr -= 8;
            }
        }

        // Process matrix2
        colIndex = 0;
        for (int j = 0; j < nCols2; j++)
        {
            result[ptrIndex] |= (matrix2[colIndex] << (8 - offPtr));

            for (int i = 0; i < nRowsBytes - 1; i++)
            {
                ptrIndex++;
                result[ptrIndex] = (byte)((matrix2[colIndex] & 0xFF) >>> offPtr);
                colIndex++;
                result[ptrIndex] |= (matrix2[colIndex] << (8 - offPtr));
            }

            if (offPtr <= onCol)
            {
                ptrIndex++;
                if (offPtr < onCol)
                {
                    result[ptrIndex] = (byte)((matrix2[colIndex] & 0xFF) >>> offPtr);
                }
            }
            colIndex++;
            offPtr = (8 - ((onCol - offPtr) % 8));
            if (offPtr > 8)
            {
                offPtr -= 8;
            }
        }
    }


//    private void processColumns(byte[] result, byte[] matrix, int colCount,
//                                int bytesPerCol, int nRows, int[] ptrHolder,
//                                int[] offPtrHolder, int onCol)
//    {
//        for (int j = 0; j < colCount; j++)
//        {
//            int colStart = j * bytesPerCol;
//            byte[] column = Arrays.copyOfRange(matrix, colStart, colStart + bytesPerCol);
//
//            // Convert column to bit array (1 bit per element)
//            boolean[] bits = new boolean[nRows];
//            for (int i = 0; i < nRows; i++)
//            {
//                int byteIdx = i / 8;
//                int bitIdx = 7 - (i % 8);  // MSB first
//                bits[i] = ((column[byteIdx] >> bitIdx) & 1) != 0;
//            }
//
//            // Store bits in result with proper bit packing
//            int ptr = ptrHolder[0];
//            int offPtr = offPtrHolder[0];
//
//            for (boolean bit : bits)
//            {
//                if (offPtr == 8)
//                {
//                    ptr++;
//                    offPtr = 0;
//                    if (ptr >= result.length)
//                    {
//                        result = Arrays.copyOf(result, result.length + 1);
//                    }
//                    result[ptr] = 0;
//                }
//
//                if (bit)
//                {
//                    result[ptr] |= (1 << (7 - offPtr));
//                }
//                offPtr++;
//            }
//
//            // Handle column alignment
//            if (offPtr > onCol)
//            {
//                ptr++;
//                offPtr = 8 - (onCol - (offPtr - 8));
//            }
//
//            ptrHolder[0] = ptr;
//            offPtrHolder[0] = offPtr;
//        }
//    }

//    private void processColumns(byte[] result, byte[] matrix, int colCount,
//                                int bytesPerCol, int nRows, int[] ptrHolder,
//                                int[] offPtrHolder, int onCol)
//    {
//        for (int j = 0; j < colCount; j++)
//        {
//            int colStart = j * bytesPerCol;
//            for (int i = 0; i < bytesPerCol; i++)
//            {
//                byte current = matrix[colStart + i];
//
//                // Process upper nibble
//                byte nibble = (byte)((current & 0xF0) >>> 4);
//                processNibble(result, nibble, ptrHolder, offPtrHolder, onCol);
//
//                // Process lower nibble if needed
//                if (i < bytesPerCol - 1 || (nRows % 2 == 0))
//                {
//                    nibble = (byte)(current & 0x0F);
//                    processNibble(result, nibble, ptrHolder, offPtrHolder, onCol);
//                }
//            }
//        }
//    }

    private static void vectorAdd(byte[] result, byte[] a, byte[] b)
    {
        for (int i = 0; i < result.length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }
    }

    private static byte ffMultiply(byte a, byte b)
    {
        return MIRATH_FF_MULT_TABLE[(a & 0x0F) + 16 * (b & 0x0F)];
    }

    private void mirathPrngInit(SHAKEDigest prng, byte[] salt, byte[] seedSk, int seedSizeBytes)
    {
        int saltLength = (salt != null) ? salt.length : 0;
        byte[] input = new byte[saltBytes + seedSizeBytes];
        Arrays.fill(input, (byte)0);

        int position = 0;
        if (salt != null && salt.length >= saltBytes)
        {
            System.arraycopy(salt, 0, input, 0, saltBytes);
            position += saltBytes;
        }

        if (seedSk != null && seedSk.length >= seedSizeBytes)
        {
            System.arraycopy(seedSk, 0, input, position, seedSizeBytes);
            position += seedSizeBytes;
        }

        prng.update(input, 0, position);
    }

    private void mirathMatrixSetToFF(byte[] matrix, int nRows, int nCols)
    {
        if (isA)
        {
            if ((nRows & 1) != 0)
            {
                int matrixHeight = mirathMatrixFfBytesPerColumn(nRows);
                int matrixHeightX = matrixHeight - 1;

                for (int i = 0; i < nCols; i++)
                {
                    int index = i * matrixHeight + matrixHeightX;
                    matrix[index] &= 0x0F; // Clear upper 4 bits
                }
            }
        }
        else
        {
            if ((nRows & 7) != 0)
            {
                int matrixHeight = mirathMatrixFfBytesPerColumn(nRows);
                int matrixHeightX = matrixHeight - 1;

                byte mask = (byte)(0xff >>> (8 - (nRows % 8)));

                for (int i = 0; i < nCols; i++)
                {
                    int index = i * matrixHeight + matrixHeightX;
                    matrix[index] &= mask; // Clear upper 4 bits
                }
            }
        }
    }

    private int mirathMatrixFfBytesPerColumn(int nRows)
    {
        if (isA)
        {
            return (nRows + 1) >> 1;
        }
        else
        {
            return (nRows + 7) >> 3;
        }
    }

    int calculateMatrixBytes(int rows, int cols)
    {
        return cols * mirathMatrixFfBytesPerColumn(rows);
    }

    // Commit grid list implementation
    public void mirathTcithCommitSetAsGridList(
        byte[][][][] seeds,
        byte[][][][] input1,
        byte[][][][] input2)
    {

        // Copy input1
        for (int i = 0; i < tau1; i++)
        {
            seeds[i] = input1[i];
        }

        // Copy input2
        for (int i = 0; i < tau2; i++)
        {
            seeds[i + tau1] = input2[i];
        }
    }

    // Secret key decompression
    public void mirathMatrixDecompressSecretKey(
        byte[] S,
        byte[] C,
        byte[] H,
        byte[] pk,
        byte[] sk)
    {

        byte[] seedSk = Arrays.copyOfRange(sk, 0, securityBytes);
        byte[] seedPk = Arrays.copyOfRange(sk, securityBytes, 2 * securityBytes);
        byte[] y = new byte[ffYBytes];

        // Expand matrices from seeds
        mirathMatrixExpandSeedPublicMatrix(H, seedPk);
        mirathMatrixExpandSeedSecretMatrix(S, C, seedSk);

        // Compute y and build public key
        mirathMatrixComputeY(y, S, C, H);
        unparsePublicKey(pk, seedPk, y);
    }

    // Helper methods
    private void unparsePublicKey(byte[] pk, byte[] seedPk, byte[] y)
    {
        System.arraycopy(seedPk, 0, pk, 0, securityBytes);
        System.arraycopy(y, 0, pk, securityBytes, ffYBytes);
    }

    public void mirathMultivcCommit(byte[][] seeds, byte[] hCom, byte[][] tree,
                                    byte[][][] commits, byte[] salt, byte[] rseed)
    {

        // Initialize tree
        System.arraycopy(rseed, 0, tree[0], 0, securityBytes);
        mirathGGMTreeExpand(tree, salt);
        mirathGGMTreeGetLeaves(seeds, tree);

        // Initialize hash
        SHA3Digest hash = getSHA3Digest();
        hash.update((byte)domainSeparatorCommitment);

        // Process commits
        for (int e = 0; e < tau; e++)
        {
            int N = e < tau1 ? n1 : n2;
            for (int i = 0; i < N; i++)
            {
                int idx = mirathTcithPsi(i, e);
                mirathTcithCommit(commits[e][i], salt, e, i, seeds[idx]);
                hash.update(commits[e][i], 0, commits[e][i].length);
            }

            //hash.update(commits[e], 0, N * 2 * securityBytes);
        }

        // Finalize hash
        byte[] tempHash = new byte[hash.getDigestSize()];
        hash.doFinal(tempHash, 0);
        System.arraycopy(tempHash, 0, hCom, 0, securityBytes);
    }

    private void mirathGGMTreeExpand(byte[][] tree, byte[] salt)
    {
        for (int i = 0; i < treeLeaves - 1; i++)
        {
            byte[][] children = new byte[2][securityBytes];
            mirathExpandSeed(children, salt, i, tree[i]);

            System.arraycopy(children[0], 0, tree[2 * i + 1], 0, securityBytes);
            System.arraycopy(children[1], 0, tree[2 * i + 2], 0, securityBytes);
        }
    }

    private void mirathExpandSeed(byte[][] pairNode, byte[] salt, int idx, byte[] seed)
    {
        BlockCipher aes = AESEngine.newInstance();
        byte[] msg = new byte[16];
        byte[] keyBytes = Arrays.copyOf(seed, 16);

        // Expand key
        KeyParameter key = new KeyParameter(keyBytes);
        aes.init(true, key);

        // Process first block
        System.arraycopy(salt, 0, msg, 0, saltBytes);
        msg[0] ^= 0x00;
        Pack.intToLittleEndian(idx, msg, 1);
        msg[5] ^= domainSeparatorPrg;
        aes.processBlock(msg, 0, pairNode[0], 0);

        // Process second block
        msg[0] ^= 0x01;
        aes.processBlock(msg, 0, pairNode[1], 0);
    }

    private void mirathGGMTreeGetLeaves(byte[][] output, byte[][] tree)
    {
        int firstLeaf = treeLeaves - 1;
        for (int i = firstLeaf; i < tree.length; i++)
        {
            System.arraycopy(tree[i], 0, output[i - firstLeaf], 0, securityBytes);
        }
    }

    private int mirathTcithPsi(int i, int e)
    {
        if (i < n2)
        {
            return i * tau + e;
        }
        else
        {
            return n2 * tau +
                (i - n2) * tau1 + e;
        }
    }

    private void mirathTcithCommit(byte[] commit, byte[] salt, int e, int i, byte[] seed)
    {
        int idx = mirathTcithPsi(i, e);
        mirathCommit(commit, salt, treeLeaves + idx, seed);
    }

    private void mirathCommit(byte[] commit, byte[] salt, int idx, byte[] seed)
    {
        byte[][] pairNode = new byte[2][securityBytes];
        mirathExpandSeed(pairNode, salt, idx, seed);
        System.arraycopy(pairNode[0], 0, commit, 0, securityBytes);
        System.arraycopy(pairNode[1], 0, commit, securityBytes, securityBytes);
    }

    private SHA3Digest getSHA3Digest()
    {
        switch (securityBytes)
        {
        case 16:
            return new SHA3Digest(256);
        case 24:
            return new SHA3Digest(384);
        case 32:
            return new SHA3Digest(512);
        default:
            throw new IllegalArgumentException("Unsupported security bytes size");
        }
    }

    // AES Operations
    public static void mirathExpandShare(byte[][] sample, byte[] salt, byte[] seed)
    {
        AESEngine aes = new AESEngine();
        KeyParameter key = new KeyParameter(Arrays.copyOf(seed, 16));
        aes.init(true, key);

        byte[] ctr = new byte[16];
        for (int i = 0; i < sample.length; i++)
        {
            ctr[0] = (byte)i;
            byte[] msg = new byte[16];
            for (int k = 0; k < 16; k++)
            {
                msg[k] = (byte)(ctr[k] ^ salt[k]);
            }
            aes.processBlock(msg, 0, sample[i], 0);
        }
    }

    // Matrix Operations
    public static void mirathMatrixFFAdd(byte[] matrix1, byte[] matrix2, byte[] matrix3,
                                         int nRows, int nCols)
    {
        int bytes = mirathMatrixFFBytesSize(nRows, nCols);
        for (int i = 0; i < bytes; i++)
        {
            matrix1[i] = (byte)(matrix2[i] ^ matrix3[i]);
        }
    }

    // Vector Operations
    public static void mirathVectorFFMuAdd(byte[] vector1, byte[] vector2, byte[] vector3,
                                           int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            vector1[i] = (byte)(vector2[i] ^ vector3[i]);
        }
    }

    // Matrix-Vector Operations
    public static void mirathMatrixFFMuAddMultipleFF(byte[] matrix1, byte scalar, byte[] matrix2,
                                                     int nRows, int nCols)
    {
        for (int i = 0; i < nRows; i++)
        {
            for (int j = 0; j < nCols; j++)
            {
                byte entry1 = mirathMatrixFFMuGetEntry(matrix1, nRows, i, j);
                byte entry2 = mirathMatrixFFGetEntry(matrix2, nRows, i, j);
                byte entry3 = (byte)(entry1 ^ mirathFFMuMult(scalar, entry2));
                mirathMatrixFFMuSetEntry(matrix1, nRows, i, j, entry3);
            }
        }
    }

    private static void mirathMatrixFFMuSetEntry(byte[] m, int n, int i, int j, byte v)
    {
        m[j * n + i] = v;
    }

    private static byte mirathMatrixFFMuGetEntry(byte[] m, int n, int i, int j)
    {
        return m[n * j + i];
    }

    // Helper methods
    private static byte mirathFFMuMult(byte a, byte b)
    {
        int idx = (b & 0xff) << 3;
        byte tmp = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((a & (1 << i)) != 0)
            {
                tmp ^= MIRATH_FF_MU_MULT_BASE[i + idx];
            }
        }
        return tmp;
    }

    private static byte mirathMatrixFFGetEntry(byte[] matrix, int nRows, int i, int j)
    {
        int bytesPerCol = mirathMatrixFFBytesPerColumn(nRows);
        int pos = j * bytesPerCol + (i >> 1);
        return (byte)((i & 1) != 0 ?
            (matrix[pos] >> 4) & 0x0F :
            matrix[pos] & 0x0F);
    }

    private static int mirathMatrixFFBytesPerColumn(int nRows)
    {
        return (nRows >> 1) + (nRows & 1);
    }

    private static int mirathMatrixFFBytesSize(int nRows, int nCols)
    {
        return nCols * mirathMatrixFFBytesPerColumn(nRows);
    }

    // Hashing Operations
    public void mirathTcithHashSh(byte[] hSh, byte[] salt, byte[] hCom, byte[][] aux)
    {
        SHA3Digest digest = new SHA3Digest(512);
        digest.update((byte)domainSeparatorHash1);
        digest.update(salt, 0, saltBytes);
        digest.update(hCom, 0, hCom.length);

        for (byte[] auxEntry : aux)
        {
            digest.update(auxEntry, 0, auxEntry.length);
        }

        digest.doFinal(hSh, 0);
    }

    public void commitParallelSharings(
        byte[][][] S_base, byte[][][] C_base, byte[][][] v_base,
        byte[][][] v, byte[] hSh, byte[][] tree,
        byte[][][] commits, byte[][] aux, byte[] salt,
        byte[] rseed, byte[] S, byte[] C)
    {

        // Initialize arrays
        for (byte[][] arr : S_base)
        {
            Arrays.fill(arr, (byte)0);
        }
        for (byte[][] arr : C_base)
        {
            Arrays.fill(arr, (byte)0);
        }
        for (byte[][] arr : v_base)
        {
            Arrays.fill(arr, (byte)0);
        }
        for (byte[][] arr : v)
        {
            Arrays.fill(arr, (byte)0);
        }
        for (byte[] arr : aux)
        {
            Arrays.fill(arr, (byte)0);
        }

        byte[] hCom = new byte[2 * securityBytes];
        byte[][] seeds = new byte[treeLeaves][securityBytes];

        mirathMultivcCommit(seeds, hCom, tree, commits, salt, rseed);

        for (int e = 0; e < tau; e++)
        {
            int N = e < tau1 ? n1 : n2;

            byte[] S_acc = new byte[mirathMatrixFFBytesSize(m, r)];
            byte[] C_acc = new byte[mirathMatrixFFBytesSize(r, n - r)];

            for (int i = 0; i < N; i++)
            {
                int idx = mirathTcithPsi(i, e);
                byte[][] sample = new byte[blockLength][securityBytes];
                mirathExpandShare(sample, salt, seeds[idx]);

                byte[] sampleFlat = flatten(sample);
//
//                byte[] S_rnd = Arrays.copyOfRange(sampleFlat, 0, varFFSBytes);
//                mirathMatrixSetToFF(S_rnd, m, r);
//
//                byte[] C_rnd = Arrays.copyOfRange(sampleFlat, varFFSBytes, varFFSBytes + varFFCBytes);
//                mirathMatrixSetToFF(C_rnd, r, n - r);
//
//                byte[] v_rnd = Arrays.copyOfRange(sampleFlat, varFFSBytes + varFFCBytes, varFFSBytes + varFFCBytes + rho);
//
//                mirathMatrixFFAdd(S_acc, S_acc, S_rnd, m, r);
//                mirathMatrixFFAdd(C_acc, C_acc, C_rnd, r, n - r);
//                mirathVectorFFMuAdd(v[e], v[e], v_rnd, rho);
//
//                byte phi_i = (byte)i;
//
//                mirathMatrixFFMuAddMultipleFF(S_base[e], phi_i, S_rnd, m, r);
//                mirathMatrixFFMuAddMultipleFF(C_base[e], phi_i, C_rnd, r, n - r);
//                mirathVectorFFMuAddMultiple(v_base[e], v_base[e], phi_i, v_rnd, rho);
            }

            // S - acc_S
            mirathMatrixFFAdd(aux[e], S, S_acc, m, r);

            int offset = mirathMatrixFFBytesSize(m, r);
            //mirathMatrixFFAdd(aux[e], offset, C, C_acc, r, n - r); // overload with offset write
        }

        mirathTcithHashSh(hSh, salt, hCom, aux);
    }

    private byte[] flatten(byte[][] input)
    {
        int totalLength = input.length * input[0].length;
        byte[] result = new byte[totalLength];
        for (int i = 0; i < input.length; i++)
        {
            System.arraycopy(input[i], 0, result, i * input[i].length, input[i].length);
        }
        return result;
    }

}
