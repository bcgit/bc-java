package org.bouncycastle.pqc.crypto.mirath;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;

class MirathEngine
{
    public final int securityBytes;
    public final int saltBytes;
    public final int m;
    public final int r;
    public final int n;
    final int n2;
    final int n1;
    public final int k;
    final int tau;
    public final int tau1;
    public final int tau2;
    final int rho;
    private final boolean isA;
    final int ffYBytes;
    final int ffSBytes;
    final int ffCBytes;
    final int ffHBytes;
    final int ffAuxBytes;
    final int baseMid;
    private final int eA;
    final int s;
    private final int t;
    private final int mu;
    final int c;
    private final int offEA;
    private final int offEB;
    private final int treeLeaves;
    private final int blockLength;
    private final int challenge2Bytes;
    private final int hash2MaskBytes;
    private final int hash2Mask;
    private final int tOpen;
    private final int leavesSeedsOffset;
    final int maxOpen;
    final int gamma;
    private final int n1Bytes;
    private final int n2Bytes;
    private final int n1Bits;
    private final int n1Mask;
    private final int n2Mask;
    private final int n2Bits;
    private final boolean isFast;
    private static final int domainSeparatorCommitment = 5;
    private static final int domainSeparatorPrg = 4;
    private static final int domainSeparatorHash1 = 1;
    private static final int domainSeparatorHash2Partial = 2;
    private static final int domainSeparatorHash2 = 3;
    private static final byte domainSeparatorCmt = 3;

    // GF(16) multiplication table (replace with actual implementation if different)
    private static final byte[] MIRATH_MAP_FF_TO_FF_MU = new byte[]{
        (byte)0, (byte)1, (byte)92, (byte)93, (byte)224, (byte)225, (byte)188, (byte)189, (byte)80, (byte)81, (byte)12, (byte)13, (byte)176, (byte)177, (byte)236, (byte)237
    };

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
        challenge2Bytes = parameters.getChallenge2Bytes();
        hash2MaskBytes = parameters.getHash2MaskBytes();
        hash2Mask = parameters.getHash2Mask();
        tOpen = parameters.getTOpen();
        n1Bytes = parameters.getN1Bytes();
        n2Bytes = parameters.getN2Bytes();
        n1Bits = parameters.getN1Bits();
        n1Mask = parameters.getN1Mask();
        n2Mask = parameters.getN2Mask();
        n2Bits = parameters.getN2Bits();
        mu = parameters.getMu();
        isFast = parameters.isFast();
        leavesSeedsOffset = treeLeaves - 1;
        maxOpen = 2 * tOpen;
        ffYBytes = calculateMatrixBytes(m * n - k, 1);
        ffSBytes = calculateMatrixBytes(m, r);
        ffCBytes = calculateMatrixBytes(r, n - r);
        ffHBytes = calculateMatrixBytes(m * n - k, k);
        ffAuxBytes = calculateMatrixBytes(m, r) + calculateMatrixBytes(r, n - r);
        baseMid = m * (n - r);
        eA = m * n - k;
        s = m * r;
        t = m * n;
        c = r * (n - r);
        gamma = rho * (m * n - k);
        blockLength = (ffSBytes + ffCBytes + rho + (securityBytes - 1)) / securityBytes;

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

    // Modified horizontalConcat caller
    private void horizontalConcat(byte[] result, byte[] matrix1, byte[] matrix2,
                                  int nRows, int nCols1, int nCols2)
    {
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
                hash.update(commits[e][i], 0, 2 * securityBytes);
            }
        }

        hash.doFinal(hCom, 0);
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
        if (securityBytes == 16)
        {
            BlockCipher aes = AESEngine.newInstance();
            byte[] msg = new byte[16];
            byte[] keyBytes = Arrays.copyOf(seed, 16);

            // Expand key
            KeyParameter key = new KeyParameter(keyBytes);
            aes.init(true, key);

            // Process first block
            System.arraycopy(salt, 0, msg, 0, msg.length);
            msg[0] ^= 0x00;
            byte[] bytes = Pack.intToLittleEndian(idx);
            Bytes.xorTo(4, bytes, 0, msg, 1);
            msg[5] ^= domainSeparatorPrg;
            aes.processBlock(msg, 0, pairNode[0], 0);

            // Process second block
            msg[0] ^= 0x01;
            aes.processBlock(msg, 0, pairNode[1], 0);
        }
        else
        {
            // Prepare 32-byte key: seed (24 bytes) + 8 zero bytes
            byte[] key = new byte[32];
            System.arraycopy(seed, 0, key, 0, seed.length);

            // Initialize Rijndael cipher with 256-bit block size
            RijndaelEngine engine = new RijndaelEngine(32 * 8); // bits
            engine.init(true, new KeyParameter(key));

            // Prepare message buffer
            byte[] msg = new byte[32];
            System.arraycopy(salt, 0, msg, 0, securityBytes);

            // First encryption: counter = 0
            byte[] idxBytes = Pack.intToLittleEndian(idx);
            Bytes.xorTo(4, idxBytes, 0, msg, 1);
            msg[5] ^= domainSeparatorPrg;
            byte[] output0 = new byte[32];
            engine.processBlock(msg, 0, output0, 0);
            System.arraycopy(output0, 0, pairNode[0], 0, securityBytes);

            // Second encryption: counter = 1
            msg[0] ^= (byte)0x01;
            byte[] output1 = new byte[32];
            engine.processBlock(msg, 0, output1, 0);
            System.arraycopy(output1, 0, pairNode[1], 0, securityBytes);
        }
    }

    public void mirathCommit(byte[][] pairNode, byte[] salt, int idx, byte[] seed)
    {
        SHA3Digest digest = getSHA3Digest();

        // Initialize hash with domain separator
        digest.update(domainSeparatorCmt);

        // Update with salt
        digest.update(salt, 0, saltBytes);

        // Update with index i (big-endian 4 bytes)
        byte[] iBytes = Pack.longToLittleEndian(idx);
        digest.update(iBytes, 0, 4);

        // Update with seed
        digest.update(seed, 0, securityBytes);

        // Finalize hash into pairNode
        byte[] hashResult = new byte[64]; // 2 * securityBytes
        digest.doFinal(hashResult, 0);

        // Split hash result into two parts
        System.arraycopy(hashResult, 0, pairNode[0], 0, securityBytes);
        System.arraycopy(hashResult, securityBytes, pairNode[1], 0, securityBytes);
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
            return n2 * tau + (i - n2) * tau1 + e;
        }
    }

    private void mirathTcithCommit(byte[] commit, byte[] salt, int e, int i, byte[] seed)
    {
        int idx = mirathTcithPsi(i, e);
        mirathCommit(commit, salt, idx, seed);
    }

    private void mirathCommit(byte[] commit, byte[] salt, int idx, byte[] seed)
    {
        byte[][] pairNode = new byte[2][securityBytes];
        mirathCommit(pairNode, salt, idx, seed);
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

    private int getShakeDigest()
    {
        switch (securityBytes)
        {
        case 16:
            return 128;
        case 24:
        case 32:
            return 256;
        default:
            throw new IllegalArgumentException("Unsupported security bytes size");
        }
    }

    // Matrix Operations
    public void mirathMatrixFFAdd(byte[] matrix1, byte[] matrix2, byte[] matrix3, int nRows, int nCols)
    {
        int bytes = mirathMatrixFFBytesSize(nRows, nCols);
        for (int i = 0; i < bytes; i++)
        {
            matrix1[i] = (byte)(matrix2[i] ^ matrix3[i]);
        }
    }

    // Vector Operations
    public static void mirathVectorFFMuAdd(byte[] vector1, byte[] vector2, byte[] vector3, int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            vector1[i] = (byte)(vector2[i] ^ vector3[i]);
        }
    }

    public static void mirathVectorFFMuAdd(short[] vector1, short[] vector2, short[] vector3, int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            vector1[i] = (short)(vector2[i] ^ vector3[i]);
        }
    }

    private static void mirathMatrixFFMuSetEntry(byte[] m, int n, int i, int j, byte v)
    {
        m[j * n + i] = v;
    }

    private static void mirathMatrixFFMuSetEntry(short[] m, int n, int i, int j, short v)
    {
        m[j * n + i] = v;
    }

    private static byte mirathMatrixFFMuGetEntry(byte[] m, int n, int i, int j)
    {
        return m[n * j + i];
    }

    private static short mirathMatrixFFMuGetEntry(short[] m, int n, int i, int j)
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

    public short mirathFFMuMult(short a, short b)
    {
        if (isA)
        {
            // Extract 4-bit limbs from 12-bit values (stored in 16-bit space)
            int a0 = a & 0xF;
            int a1 = (a >> 4) & 0xF;
            int a2 = (a >> 8) & 0xF;

            int b0 = b & 0xF;
            int b1 = (b >> 4) & 0xF;
            int b2 = (b >> 8) & 0xF;

            // Compute basic products
            int p0 = mirathFfProduct(a0, b0);
            int p1 = mirathFfProduct(a1, b1);
            int p2 = mirathFfProduct(a2, b2);

            // Compute intermediate sums
            int a01 = a0 ^ a1;
            int a12 = a1 ^ a2;
            int a02 = a0 ^ a2;
            int b01 = b0 ^ b1;
            int b12 = b1 ^ b2;
            int b02 = b0 ^ b2;

            // Compute cross products
            int p01 = mirathFfProduct(a01, b01);
            int p12 = mirathFfProduct(a12, b12);
            int p02 = mirathFfProduct(a02, b02);

            // Combine terms
            int r = p1 ^ p2;
            r = r ^ p12;
            r = r ^ p0;

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
                tmp = (short)((tmp << 1) ^ (-(tmp >> 11) & 0x1009));
                result ^= (-(a >> i & 1) & tmp);
            }
            return result;
        }
    }

    private static int mirathFfProduct(int a, int b)
    {
        // Mask to 4 bits and lookup
        return MIRATH_FF_MULT_TABLE[a + b * 16] & 0xFF;
    }

    private byte mirathMatrixFFGetEntry(byte[] matrix, int nRows, int i, int j)
    {
        int bytesPerCol = mirathMatrixFfBytesPerColumn(nRows);
        if (isA)
        {
            int pos = j * bytesPerCol + (i >> 1);
            return (byte)((i & 1) != 0 ? (matrix[pos] >> 4) & 0x0F : matrix[pos] & 0x0F);
        }
        else
        {
            return (byte)((matrix[bytesPerCol * j + (i >> 3)] >> (i & 7)) & 0x01);
        }
    }

    private int mirathMatrixFFBytesSize(int nRows, int nCols)
    {
        return nCols * mirathMatrixFfBytesPerColumn(nRows);
    }

    public void commitParallelSharings(
        byte[][] S_base, byte[][] C_base,
        byte[][] v_base, byte[][] v,
        byte[] hSh, byte[][] tree,
        byte[][][] commits, byte[][] aux,
        byte[] salt, byte[] rseed,
        byte[] S, byte[] C)
    {
        byte[] hCom = new byte[2 * securityBytes];
        byte[][] seeds = new byte[treeLeaves][securityBytes];

        // Generate commitments
        mirathMultivcCommit(seeds, hCom, tree, commits, salt, rseed);

        // Process each tau element
        for (int e = 0; e < tau; e++)
        {
            int N = e < tau1 ? n1 : n2;
            byte[] S_acc = new byte[ffSBytes];
            byte[] C_acc = new byte[ffCBytes];

            for (int i = 0; i < N; i++)
            {
                int idx = mirathTcithPsi(i, e);
                byte[] sample = new byte[blockLength * securityBytes];

                // Expand shares using AES
                mirathExpandShare(sample, salt, seeds[idx]);

                // Extract components from sample
                byte[] S_rnd = Arrays.copyOf(sample, ffSBytes);
                mirathMatrixSetToFF(S_rnd, m, r);
                byte[] C_rnd = Arrays.copyOfRange(sample, ffSBytes, ffSBytes + ffCBytes);
                mirathMatrixSetToFF(C_rnd, r, n - r);
                byte[] v_rnd = Arrays.copyOfRange(sample, ffSBytes + ffCBytes, ffSBytes + ffCBytes + rho);

                // Performs S_acc = S_acc + S_rnd, C_acc = C_acc + C_rnd and v[e] = v[e] + v_rnd
                mirathMatrixFFAdd(S_acc, S_acc, S_rnd, m, r);
                mirathMatrixFFAdd(C_acc, C_acc, C_rnd, r, n - r);
                mirathVectorFFMuAdd(v[e], v[e], v_rnd, rho);

                for (int j = 0; j < rho; ++j)
                {
                    // this works only for (q=2, mu=12) and (q=16, mu=3)
                    v_rnd[j] &= 0x0FFF;
                }

                // Update base matrices with finite field operations
                byte phi_i = (byte)i;
                mirathMatrixFFMuAddMultipleFF(S_base[e], phi_i, S_rnd, m, r);
                mirathMatrixFFMuAddMultipleFF(C_base[e], phi_i, C_rnd, r, n - r);
                mirathVectorFFMuAddMultiple(v_base[e], v_base[e], phi_i, v_rnd, rho);
            }

            // Update auxiliary data
            updateAuxiliaryData(e, S_acc, C_acc, S, C, aux);
        }

        // Final hash computation
        computeFinalHash(hSh, salt, hCom, aux);
    }

    public void commitParallelSharings(
        short[][] S_base, short[][] C_base,
        short[][] v_base, short[][] v,
        byte[] hSh, byte[][] tree,
        byte[][][] commits, byte[][] aux,
        byte[] salt, byte[] rseed,
        byte[] S, byte[] C)
    {
        byte[] hCom = new byte[2 * securityBytes];
        byte[][] seeds = new byte[treeLeaves][securityBytes];

        // Generate commitments
        mirathMultivcCommit(seeds, hCom, tree, commits, salt, rseed);

        // Process each tau element
        for (int e = 0; e < tau; e++)
        {
            int N = e < tau1 ? n1 : n2;
            byte[] S_acc = new byte[ffSBytes];
            byte[] C_acc = new byte[ffCBytes];

            for (int i = 0; i < N; i++)
            {
                int idx = mirathTcithPsi(i, e);
                byte[] sample = new byte[blockLength * securityBytes];

                // Expand shares using AES
                mirathExpandShare(sample, salt, seeds[idx]);

                // Extract components from sample
                byte[] S_rnd = Arrays.copyOf(sample, ffSBytes);
                mirathMatrixSetToFF(S_rnd, m, r);
                byte[] C_rnd = Arrays.copyOfRange(sample, ffSBytes, ffSBytes + ffCBytes);
                mirathMatrixSetToFF(C_rnd, r, n - r);
                short[] v_rnd = new short[rho];
                Pack.littleEndianToShort(sample, ffSBytes + ffCBytes, v_rnd, 0, rho >> 1);
                if ((rho & 1) != 0)
                {
                    v_rnd[rho >> 1] = (short)(sample[ffSBytes + ffCBytes + rho - 1] & 0xff);
                }
                for (int j = 0; j < rho; ++j)
                {
                    // this works only for (q=2, mu=12) and (q=16, mu=3)
                    v_rnd[j] &= 0x0FFF;
                }
                // Performs S_acc = S_acc + S_rnd, C_acc = C_acc + C_rnd and v[e] = v[e] + v_rnd
                mirathMatrixFFAdd(S_acc, S_acc, S_rnd, m, r);
                mirathMatrixFFAdd(C_acc, C_acc, C_rnd, r, n - r);
                mirathVectorFFMuAdd(v[e], v[e], v_rnd, rho);

                // Update base matrices with finite field operations
                short phi_i = (short)i;
                mirathMatrixFFMuAddMultipleFF(S_base[e], phi_i, S_rnd, m, r);
                mirathMatrixFFMuAddMultipleFF(C_base[e], phi_i, C_rnd, r, n - r);
                mirathVectorFFMuAddMultiple(v_base[e], v_base[e], phi_i, v_rnd, rho);
            }

            // Update auxiliary data
            updateAuxiliaryData(e, S_acc, C_acc, S, C, aux);
        }

        // Final hash computation
        computeFinalHash(hSh, salt, hCom, aux);
    }

    private void mirathExpandShare(byte[] sample, byte[] salt, byte[] seed)
    {
        int sampleOff = 0;
        if (securityBytes == 16)
        {
            BlockCipher aes = AESEngine.newInstance();
            KeyParameter key = new KeyParameter(Arrays.copyOf(seed, 16));
            aes.init(true, key);

            byte[] ctr = new byte[16];
            for (int i = 0; i < blockLength; i++)
            {
                ctr[0] = (byte)i;
                byte[] msg = new byte[16];
                for (int k = 0; k < 16; k++)
                {
                    msg[k] = (byte)(ctr[k] ^ salt[k % salt.length]);
                }
                aes.processBlock(msg, 0, sample, sampleOff);
                sampleOff += 16;
            }
        }
        else
        {
            // 1) Build the 256-bit key = seed || 8 zero bytes
            byte[] keyBytes = new byte[32];
            System.arraycopy(seed, 0, keyBytes, 0, securityBytes);

            // 2) Init Rijndael-256 cipher for encryption
            RijndaelEngine engine = new RijndaelEngine(32 * 8);
            engine.init(true, new KeyParameter(keyBytes));

            // 3) Prepare CTR buffer (only ctr[0] changes)
            byte[] ctr = new byte[32]; // all zeros initially

            // temp buffers
            byte[] msg = new byte[32];
            byte[] output = new byte[32];

            // 4) Loop: for each share, set ctr[0]=i, xor with salt, encrypt
            for (int i = 0; i < blockLength; i++)
            {
                ctr[0] = (byte)i;

                // Build msg = ctr ⊕ salt for the first 24 bytes, rest stay zero
                for (int k = 0; k < securityBytes; k++)
                {
                    msg[k] = (byte)(ctr[k] ^ salt[k]);
                }
                // Encrypt one block
                engine.processBlock(msg, 0, output, 0);

                // Copy first 24 bytes into dst[i]
                System.arraycopy(output, 0, sample, sampleOff, securityBytes);
                sampleOff += securityBytes;
            }
        }
    }

    private void updateAuxiliaryData(int e, byte[] S_acc, byte[] C_acc,
                                     byte[] S, byte[] C, byte[][] aux)
    {
        // S - acc_S
        byte[] S_diff = new byte[ffSBytes];
        mirathMatrixFFAdd(S_diff, S, S_acc, m, r);
        System.arraycopy(S_diff, 0, aux[e], 0, S_diff.length);

        // C - acc_C
        byte[] C_diff = new byte[ffCBytes];
        mirathMatrixFFAdd(C_diff, C, C_acc, r, n - r);
        System.arraycopy(C_diff, 0, aux[e], S_diff.length, C_diff.length);
    }

    private void computeFinalHash(byte[] hSh, byte[] salt, byte[] hCom, byte[][] aux)
    {
        SHA3Digest digest = getSHA3Digest();
        digest.update((byte)0x01); // DOMAIN_SEPARATOR_HASH1
        digest.update(salt, 0, salt.length);
        digest.update(hCom, 0, hCom.length);

        for (byte[] auxEntry : aux)
        {
            digest.update(auxEntry, 0, auxEntry.length);
        }

        digest.doFinal(hSh, 0);
    }

    // Matrix/Vector Operations
    public void mirathMatrixFFMuAddMultipleFF(byte[] matrix, byte scalar, byte[] src,
                                              int nRows, int nCols)
    {
        for (int i = 0; i < nRows; i++)
        {
            for (int j = 0; j < nCols; j++)
            {
                byte entry1 = mirathMatrixFFMuGetEntry(matrix, nRows, i, j);
                byte entry2 = MIRATH_MAP_FF_TO_FF_MU[mirathMatrixFFGetEntry(src, nRows, i, j)];
                byte product = mirathFFMuMult(scalar, entry2);
                mirathMatrixFFMuSetEntry(matrix, nRows, i, j, (byte)(entry1 ^ product));
            }
        }
    }

    public void mirathMatrixFFMuAddMultipleFF(short[] matrix, short scalar, byte[] src,
                                              int nRows, int nCols)
    {
        for (int i = 0; i < nRows; i++)
        {
            for (int j = 0; j < nCols; j++)
            {
                short entry1 = mirathMatrixFFMuGetEntry(matrix, nRows, i, j);
                short entry2 = mirathMatrixFFGetEntry(src, nRows, i, j);
                short product = mirathFFMuMult(scalar, entry2);
                mirathMatrixFFMuSetEntry(matrix, nRows, i, j, (short)(entry1 ^ product));
            }
        }
    }

    /**
     * Performs vector1 = vector2 + scalar * vector3 in GF(2^8)
     *
     * @param vector1 Destination vector (modified in-place)
     * @param vector2 First operand vector
     * @param scalar  Scalar multiplier
     * @param vector3 Second operand vector
     * @param ncols   Number of elements to process
     */
    public static void mirathVectorFFMuAddMultiple(
        byte[] vector1,
        byte[] vector2,
        byte scalar,
        byte[] vector3,
        int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            // GF(2^8) multiplication followed by addition (XOR)
            vector1[i] = (byte)(vector2[i] ^ mirathFFMuMult(scalar, vector3[i]));
        }
    }

    public void mirathVectorFFMuAddMultiple(
        short[] vector1,
        short[] vector2,
        short scalar,
        short[] vector3,
        int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            // GF(2^8) multiplication followed by addition (XOR)
            vector1[i] = (short)(vector2[i] ^ mirathFFMuMult(scalar, vector3[i]));
        }
    }

    public void mirathVectorFFMuAddMultipleFF(
        byte[] vector1,
        byte[] vector2,
        byte scalar,
        byte[] vector3,
        int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            byte t = getMatrixEntry(vector3, 1, i, 0);
            // GF(2^8) multiplication followed by addition (XOR)
            vector1[i] = (byte)(vector2[i] ^ mirathFFMuMult(scalar, MIRATH_MAP_FF_TO_FF_MU[t]));
        }
    }

    public void mirathTcithExpandMpcChallenge(byte[] Gamma, byte[] hSh)
    {
        SHAKEDigest prng = new SHAKEDigest(getShakeDigest());
        prng.update(hSh, 0, 2 * securityBytes);
        prng.doFinal(Gamma, 0, Gamma.length);
    }

    public void mirathTcithExpandMpcChallenge(short[] Gamma, byte[] hSh)
    {
        SHAKEDigest prng = new SHAKEDigest(getShakeDigest());
        prng.update(hSh, 0, 2 * securityBytes);
        byte[] result = new byte[Gamma.length << 1];
        prng.doFinal(result, 0, result.length);
        Pack.littleEndianToShort(result, 0, Gamma, 0, Gamma.length);
    }

    public void emulateMPCMu(
        byte[] baseAlpha, byte[] midAlpha,
        byte[] S, byte[] S_rnd,
        byte[] C, byte[] C_rnd,
        byte[] v, byte[] rnd_v,
        byte[] gamma, byte[] H)
    {

        // Temporary storage
        byte[] aux_E = new byte[baseMid];
        byte[] e_A = new byte[eA];
        byte[] e_B = new byte[k];
        byte[] tmp = new byte[eA];
        byte[] zero = new byte[s];

        // 1. aux_E = S_rnd * C_rnd
        matrixFFMuProduct(aux_E, S_rnd, C_rnd, m, r, n - r);

        // 2. Split codeword
        splitCodewordFFMu(e_A, e_B, zero, aux_E);

        // 3. H * e_B
        matrixFFMuProductFF1Mu(tmp, H, e_B, m * n - k, k, 1);

        // 4. e_A + (H * e_B)
        mirathVectorFFMuAdd(tmp, tmp, e_A, eA);

        // 5. gamma * [e_A + (H * e_B)]
        matrixFFMuProduct(baseAlpha, gamma, tmp, rho, m * n - k, 1);

        // 6. gamma * [e_A + (H * e_B)] + rnd_V
        mirathVectorFFMuAdd(baseAlpha, baseAlpha, rnd_v, rho);

        // 7. Intermediate calculations
        byte[] aux_s = new byte[s];
        byte[] aux_c = new byte[c];
        byte[] aux_sc = new byte[baseMid];
        byte[] sc = new byte[calculateFFBytes(m, n - r)];

        // 8. aux_s = S_rnd + S
        matrixFFMuAddMu1FF(aux_s, S_rnd, S, m, r);

        // 9. aux_c = C_rnd + C
        matrixFFMuAddMu1FF(aux_c, C_rnd, C, r, n - r);

        // 10. aux_sc = aux_s * aux_c
        matrixFFMuProduct(aux_sc, aux_s, aux_c, m, r, n - r);

        // 11. aux_E = aux_E + aux_sc
        matrixFFMuAdd(aux_E, aux_E, aux_sc, m, n - r);

        // 12. sc = S * C
        matrixFFProduct(sc, S, C, m, r, n - r);

        // 13. aux_E = aux_E + sc
        matrixFFMuAddMu1FF(aux_E, aux_E, sc, m, n - r);

        // 14. Split codeword again
        splitCodewordFFMu(e_A, e_B, S_rnd, aux_E);

        // 15. H * e'_B
        matrixFFMuProductFF1Mu(tmp, H, e_B, m * n - k, k, 1);

        // 16. e'_A + (H * e'_B)
        vectorFFMuAdd(tmp, tmp, e_A, eA);

        // 17. gamma * [e'_A + (H * e'_B)]
        matrixFFMuProduct(midAlpha, gamma, tmp, rho, m * n - k, 1);

        // 18. gamma * [e_A + (H * e_B)] + v
        vectorFFMuAdd(midAlpha, midAlpha, v, rho);
    }

    public void emulateMPCMu(
        short[] baseAlpha, short[] midAlpha,
        byte[] S, short[] S_rnd,
        byte[] C, short[] C_rnd,
        short[] v, short[] rnd_v,
        short[] gamma, byte[] H)
    {

        // Temporary storage
        short[] aux_E = new short[baseMid];
        short[] e_A = new short[eA];
        short[] e_B = new short[k];
        short[] tmp = new short[eA];
        short[] zero = new short[s];

        // 1. aux_E = S_rnd * C_rnd
        matrixFFMuProduct(aux_E, S_rnd, C_rnd, m, r, n - r);

        // 2. Split codeword
        splitCodewordFFMu(e_A, e_B, zero, aux_E);

        // 3. H * e_B
        matrixFFMuProductFF1Mu(tmp, H, e_B, m * n - k, k, 1);

        // 4. e_A + (H * e_B)
        mirathVectorFFMuAdd(tmp, tmp, e_A, eA);

        // 5. gamma * [e_A + (H * e_B)]
        matrixFFMuProduct(baseAlpha, gamma, tmp, rho, m * n - k, 1);

        // 6. gamma * [e_A + (H * e_B)] + rnd_V
        mirathVectorFFMuAdd(baseAlpha, baseAlpha, rnd_v, rho);

        // 7. Intermediate calculations
        short[] aux_s = new short[s];
        short[] aux_c = new short[c];
        short[] aux_sc = new short[baseMid];
        byte[] sc = new byte[calculateFFBytes(m, n - r)];

        // 8. aux_s = S_rnd + S
        matrixFFMuAddMu1FF(aux_s, S_rnd, S, m, r);

        // 9. aux_c = C_rnd + C
        matrixFFMuAddMu1FF(aux_c, C_rnd, C, r, n - r);

        // 10. aux_sc = aux_s * aux_c
        matrixFFMuProduct(aux_sc, aux_s, aux_c, m, r, n - r);

        // 11. aux_E = aux_E + aux_sc
        matrixFFMuAdd(aux_E, aux_E, aux_sc, m, n - r);

        // 12. sc = S * C
        matrixFFProduct(sc, S, C, m, r, n - r);

        // 13. aux_E = aux_E + sc
        matrixFFMuAddMu1FF(aux_E, aux_E, sc, m, n - r);

        // 14. Split codeword again
        splitCodewordFFMu(e_A, e_B, S_rnd, aux_E);

        // 15. H * e'_B
        matrixFFMuProductFF1Mu(tmp, H, e_B, m * n - k, k, 1);

        // 16. e'_A + (H * e'_B)
        vectorFFMuAdd(tmp, tmp, e_A, eA);

        // 17. gamma * [e'_A + (H * e'_B)]
        matrixFFMuProduct(midAlpha, gamma, tmp, rho, m * n - k, 1);

        // 18. gamma * [e_A + (H * e_B)] + v
        vectorFFMuAdd(midAlpha, midAlpha, v, rho);
    }

    // Matrix multiplication in GF(2^8)
    public static void matrixFFMuProduct(byte[] result, byte[] matrix1, byte[] matrix2,
                                         int nRows1, int nCols1, int nCols2)
    {
        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0; j < nCols2; j++)
            {
                byte entry_i_j = 0;
                for (int k = 0; k < nCols1; k++)
                {
                    byte entry_i_k = mirathMatrixFFMuGetEntry(matrix1, nRows1, i, k);
                    byte entry_k_j = mirathMatrixFFMuGetEntry(matrix2, nCols1, k, j);
                    entry_i_j ^= ffMuMult(entry_i_k, entry_k_j);
                }
                mirathMatrixFFMuSetEntry(result, nRows1, i, j, entry_i_j);
            }
        }
    }

    public void matrixFFMuProduct(short[] result, short[] matrix1, short[] matrix2,
                                  int nRows1, int nCols1, int nCols2)
    {
        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0; j < nCols2; j++)
            {
                short entry_i_j = 0;
                for (int k = 0; k < nCols1; k++)
                {
                    short entry_i_k = mirathMatrixFFMuGetEntry(matrix1, nRows1, i, k);
                    short entry_k_j = mirathMatrixFFMuGetEntry(matrix2, nCols1, k, j);
                    entry_i_j ^= mirathFFMuMult(entry_i_k, entry_k_j);
                }
                mirathMatrixFFMuSetEntry(result, nRows1, i, j, entry_i_j);
            }
        }
    }

    // return a*b
    public static byte ffMuMult(byte a, byte b)
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

    public void splitCodewordFFMu(byte[] e_A, byte[] e_B, byte[] in_X, byte[] in_Y)
    {
        byte[] tmp = new byte[m * n];
        System.arraycopy(in_X, 0, tmp, 0, in_X.length);
        System.arraycopy(in_Y, 0, tmp, in_X.length, in_Y.length);

        System.arraycopy(tmp, 0, e_A, 0, e_A.length);
        System.arraycopy(tmp, e_A.length, e_B, 0, e_B.length);
    }

    public void splitCodewordFFMu(short[] e_A, short[] e_B, short[] in_X, short[] in_Y)
    {
        short[] tmp = new short[m * n];
        System.arraycopy(in_X, 0, tmp, 0, in_X.length);
        System.arraycopy(in_Y, 0, tmp, in_X.length, in_Y.length);

        System.arraycopy(tmp, 0, e_A, 0, e_A.length);
        System.arraycopy(tmp, e_A.length, e_B, 0, e_B.length);
    }

    public void matrixFFProduct(byte[] result, byte[] matrix1, byte[] matrix2,
                                int nRows1, int nCols1, int nCols2)
    {
        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0; j < nCols2; j++)
            {
                byte entry_i_j = 0;
                for (int k = 0; k < nCols1; k++)
                {
                    byte entry_i_k = getMatrixEntry(matrix1, nRows1, i, k);
                    byte entry_k_j = getMatrixEntry(matrix2, nCols1, k, j);
                    entry_i_j ^= MIRATH_FF_MULT_TABLE[entry_i_k + entry_k_j * 16];
                }
                setMatrixEntry(result, nRows1, i, j, entry_i_j);
            }
        }

        if ((nRows1 & 1) == 1)
        {
            int matrixHeight = mirathMatrixFfBytesPerColumn(nRows1);
            int matrixHeight_x = matrixHeight - 1;
            for (int i = 0; i < nCols2; ++i)
            {
                result[i * matrixHeight + matrixHeight_x] &= 0x0f;
            }
        }
    }

    // Mixed Field Matrix Multiplication (GF256 * GF16)
    private void matrixFFMuProductFF1Mu(byte[] result, byte[] mat1, byte[] mat2,
                                        int rows1, int cols1, int cols2)
    {
        for (int i = 0; i < rows1; i++)
        {
            for (int j = 0; j < cols2; j++)
            {
                byte entry_i_j = 0;
                for (int k = 0; k < cols1; k++)
                {
                    byte entry_i_k = MIRATH_MAP_FF_TO_FF_MU[mirathMatrixFFGetEntry(mat1, rows1, i, k)];
                    byte entry_k_j = mirathMatrixFFMuGetEntry(mat2, cols1, k, j);
                    entry_i_j ^= ffMuMult(entry_i_k, entry_k_j);
                }
                mirathMatrixFFMuSetEntry(result, rows1, i, j, entry_i_j);
            }
        }
    }

    private void matrixFFMuProductFF1Mu(short[] result, byte[] mat1, short[] mat2,
                                        int rows1, int cols1, int cols2)
    {
        for (int i = 0; i < rows1; i++)
        {
            for (int j = 0; j < cols2; j++)
            {
                short entry_i_j = 0;
                for (int k = 0; k < cols1; k++)
                {
                    short entry_i_k = mirathMatrixFFGetEntry(mat1, rows1, i, k);
                    short entry_k_j = mirathMatrixFFMuGetEntry(mat2, cols1, k, j);
                    entry_i_j ^= mirathFFMuMult(entry_i_k, entry_k_j);
                }
                mirathMatrixFFMuSetEntry(result, rows1, i, j, entry_i_j);
            }
        }
    }

    private void matrixFFMuAddMu1FF(byte[] matrix1, byte[] matrix2, byte[] matrix3,
                                    int rows, int cols)
    {
        for (int i = 0; i < rows; i++)
        {
            for (int j = 0; j < cols; j++)
            {
                byte entry1 = mirathMatrixFFMuGetEntry(matrix2, rows, i, j);
                byte entry2 = MIRATH_MAP_FF_TO_FF_MU[mirathMatrixFFGetEntry(matrix3, rows, i, j)];
                mirathMatrixFFMuSetEntry(matrix1, rows, i, j, (byte)(entry1 ^ entry2));
            }
        }
    }

    private void matrixFFMuAddMu1FF(short[] matrix1, short[] matrix2, byte[] matrix3,
                                    int rows, int cols)
    {
        for (int i = 0; i < rows; i++)
        {
            for (int j = 0; j < cols; j++)
            {
                short entry1 = mirathMatrixFFMuGetEntry(matrix2, rows, i, j);
                short entry2 = mirathMatrixFFGetEntry(matrix3, rows, i, j);
                mirathMatrixFFMuSetEntry(matrix1, rows, i, j, (short)(entry1 ^ entry2));
            }
        }
    }

    private static int calculateFFBytes(int rows, int cols)
    {
        return cols * ((rows + 1) / 2);
    }

    // Matrix Additions
    private static void matrixFFMuAdd(byte[] result, byte[] mat1, byte[] mat2,
                                      int rows, int cols)
    {
        int totalElements = rows * cols;
        for (int i = 0; i < totalElements; i++)
        {
            result[i] = (byte)(mat1[i] ^ mat2[i]);
        }
    }

    private static void matrixFFMuAdd(short[] result, short[] mat1, short[] mat2,
                                      int rows, int cols)
    {
        int totalElements = rows * cols;
        for (int i = 0; i < totalElements; i++)
        {
            result[i] = (short)(mat1[i] ^ mat2[i]);
        }
    }

    // Vector Operations
    private static void vectorFFMuAdd(byte[] result, byte[] vec1, byte[] vec2, int length)
    {
        for (int i = 0; i < length; i++)
        {
            result[i] = (byte)(vec1[i] ^ vec2[i]);
        }
    }

    private static void vectorFFMuAdd(short[] result, short[] vec1, short[] vec2, int length)
    {
        for (int i = 0; i < length; i++)
        {
            result[i] = (short)(vec1[i] ^ vec2[i]);
        }
    }

    // Hash MPC function
    public void mirathTcithHashMpc(byte[] hMpc, byte[] pk, byte[] salt,
                                   byte[] msg, byte[] hSh,
                                   byte[][] alphaMid, byte[][] alphaBase)
    {
        SHA3Digest digest = getSHA3Digest();
        byte domainSeparator = (byte)domainSeparatorHash2Partial;

        // Initialize hash
        digest.update(domainSeparator);
        digest.update(pk, 0, pk.length);
        digest.update(salt, 0, salt.length);
        digest.update(msg, 0, msg.length);
        digest.update(hSh, 0, hSh.length);

        // Process alpha values
        for (int e = 0; e < tau; e++)
        {
            digest.update(alphaBase[e], 0, alphaBase[e].length);
            digest.update(alphaMid[e], 0, alphaMid[e].length);
        }

        // Finalize hash
        digest.doFinal(hMpc, 0);
    }

    public void mirathTcithHashMpc(byte[] hMpc, byte[] pk, byte[] salt,
                                   byte[] msg, byte[] hSh,
                                   short[][] alphaMid, short[][] alphaBase)
    {
        SHA3Digest digest = getSHA3Digest();
        byte domainSeparator = (byte)domainSeparatorHash2Partial;

        // Initialize hash
        digest.update(domainSeparator);
        digest.update(pk, 0, pk.length);
        digest.update(salt, 0, salt.length);
        digest.update(msg, 0, msg.length);
        digest.update(hSh, 0, hSh.length);

        // Process alpha values
        for (int e = 0; e < tau; e++)
        {
            byte[] tmp = Pack.shortToLittleEndian(alphaBase[e]);
            digest.update(tmp, 0, tmp.length);
            tmp = Pack.shortToLittleEndian(alphaMid[e]);
            digest.update(tmp, 0, tmp.length);
        }

        // Finalize hash
        digest.doFinal(hMpc, 0);
    }

    private void expandViewChallenge(int[] challenge, byte[] vGrinding, byte[] input)
    {
        SHAKEDigest prng = new SHAKEDigest(getShakeDigest());
        prng.update(input, 0, input.length);

        byte[] random = new byte[challenge2Bytes + hash2MaskBytes];
        prng.doFinal(random, 0, random.length);

        // Extract v_grinding and apply mask
        System.arraycopy(random, challenge2Bytes, vGrinding, 0, hash2MaskBytes);
        vGrinding[hash2MaskBytes - 1] &= (byte)hash2Mask;
        Arrays.fill(random, challenge2Bytes, random.length, (byte)0);

        int randomOffset = 0;

        // Process N1 challenges
        for (int e = 0; e < tau1; e++)
        {
            byte[] block = Arrays.copyOfRange(random, randomOffset, randomOffset + n1Bytes);
            block[n1Bytes - 1] &= n1Mask;

            challenge[e] = getChallenge(block);

            // Shift right by N1_BITS
            for (int j = 0; j < n1Bits; j++)
            {
                shiftRightArray(random, challenge2Bytes);
            }
        }

        // Process N2 challenges
        for (int e = tau1; e < tau1 + tau2; e++)
        {
            byte[] block = Arrays.copyOfRange(random, randomOffset, randomOffset + n2Bytes);
            block[n2Bytes - 1] &= n2Mask;

            challenge[e] = getChallenge(block);

            // Shift right by N2_BITS
            for (int j = 0; j < n2Bits; j++)
            {
                shiftRightArray(random, challenge2Bytes);
            }
        }
    }

    private int getChallenge(byte[] block)
    {
        if (isFast)
        {
            return block[0] & 0xff;
        }
        else
        {
            return Pack.littleEndianToShort(block, 0);
        }
    }

    // Improved bit shifting implementation
    private static void shiftRightArray(byte[] arr, int length)
    {
        for (int i = 0; i < length - 1; i++)
        {
            arr[i] = (byte)(((arr[i] & 0xff) >>> 1) ^ ((arr[i + 1] & 0xff) << 7));
        }
        arr[length - 1] = (byte)((arr[length - 1] & 0xff) >>> 1);
    }

    public byte discardInputChallenge2(byte[] vGrinding)
    {
        byte output = 0x00;
        byte mask = (byte)hash2Mask;

        for (int i = 0; i < hash2MaskBytes; i++)
        {
            if (i > 0)
            {
                mask = (byte)0xFF;
            }
            if ((vGrinding[i] & mask) != 0)
            {
                output = 0x01;
                break;
            }
        }
        return output;
    }

    public byte multivcOpen(byte[][] path, byte[][] commitsIStar,
                            byte[][] tree, byte[][][] commits,
                            int[] iStar)
    {

        int[] psiIStar = new int[tau];

        for (int e = 0; e < tau; e++)
        {
            int i = iStar[e];
            psiIStar[e] = mirathTcithPsi(i, e);
        }

        int pathLength = getSiblingPath(path, tree, psiIStar);

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
            int i = iStar[e];
            System.arraycopy(commits[e][i], 0, commitsIStar[e], 0, 2 * securityBytes);
        }
        return 0;
    }

    public int getSiblingPath(byte[][] pathSeeds, byte[][] ggmTree, int[] hiddenLeaves)
    {
        List<Integer> pathIndexes = new ArrayList<>();

        for (int leaf : hiddenLeaves)
        {
            int node = leavesSeedsOffset + leaf;
            while (node > 0)
            {
                int pos = Collections.binarySearch(pathIndexes, node);
                if (pos >= 0)
                {
                    pathIndexes.remove(pos);
                    break;
                }
                else
                {
                    int sibling = getSibling(node);
                    if (pathIndexes.size() >= maxOpen)
                    {
                        return -1;
                    }
                    int insertPos = -pos - 1;
                    pathIndexes.add(insertPos, sibling);
                }
                node = getParent(node);
            }
        }

        // Copy the seeds from the tree to the path
        for (int i = 0; i < pathIndexes.size(); i++)
        {
            int index = pathIndexes.get(i);
            System.arraycopy(ggmTree[index], 0, pathSeeds[i], 0, securityBytes);
        }

        return pathIndexes.size();
    }

    private static int getSibling(int nodeIndex)
    {
        return nodeIndex % 2 == 1 ? nodeIndex + 1 : nodeIndex - 1;
    }

    private static int getParent(int nodeIndex)
    {
        return (nodeIndex - 1) / 2;
    }

    // Corrected openRandomShare method
    public long mirathTcithOpenRandomShare(byte[][] path, byte[][] commitsIStar,
                                           byte[][] tree, byte[][][] commits,
                                           byte[] binding)
    {
        byte[] shakeInput = new byte[2 * securityBytes + Long.BYTES];
        System.arraycopy(binding, 0, shakeInput, 0, 2 * securityBytes);

        long ctr = 0;
        byte[] vGrinding = new byte[hash2MaskBytes];

        while (true)
        {
            byte[] ctrBytes = Pack.longToLittleEndian(ctr);
            System.arraycopy(ctrBytes, 0, shakeInput, 2 * securityBytes, Long.BYTES);

            int[] challenge = new int[tau];
            expandViewChallenge(challenge, vGrinding, shakeInput);

            byte result = multivcOpen(path, commitsIStar, tree, commits, challenge);
            byte discard = discardInputChallenge2(vGrinding);

            if (discard == 0 && result == 0)
            {
                return ctr;
            }

            ctr++;
            Arrays.fill(vGrinding, (byte)0);
            for (byte[] arr : path)
            {
                Arrays.fill(arr, (byte)0);
            }
        }
    }

    public void unparseSignature(byte[] signature,
                                 byte[] salt,
                                 long ctr,
                                 byte[] hash2,
                                 byte[][] path,
                                 byte[][] commitsIStar,
                                 byte[][] aux,
                                 byte[][] midAlpha)
    {
        int ptr = 0;

        // Copy salt
        System.arraycopy(salt, 0, signature, ptr, saltBytes);
        ptr += saltBytes;

        // Copy counter (little-endian)
        byte[] ctrBytes = Pack.longToLittleEndian(ctr);
        System.arraycopy(ctrBytes, 0, signature, ptr, 8);
        ptr += 8;

        // Copy hash2
        System.arraycopy(hash2, 0, signature, ptr, 2 * securityBytes);
        ptr += 2 * securityBytes;

        // Copy path
        for (int i = 0; i < tOpen; ++i)
        {
            System.arraycopy(path[i], 0, signature, ptr, securityBytes);
            ptr += securityBytes;
        }

        // Copy commits_i_star
        for (byte[] commit : commitsIStar)
        {
            System.arraycopy(commit, 0, signature, ptr, 2 * securityBytes);
            ptr += 2 * securityBytes;
        }

        // Pack field elements
        int offPtr = 8; // Tracks bits remaining in current byte
        int nRowsBytes1 = mirathMatrixFFBytesSize(m, 1); // Bytes per column for M rows
        int nRowsBytes2 = mirathMatrixFFBytesSize(r, 1); // Bytes per column for R rows
        int onCol1, onCol2;
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

        for (int e = 0; e < tau; e++)
        {
            int col = 0;
            // Process R columns (M x R matrix)
            for (int j = 0; j < r; j++)
            {
                signature[ptr] |= (aux[e][col] & 0xff) << (8 - offPtr);
                for (int i = 0; i < nRowsBytes1 - 1; ++i)
                {
                    ptr++;
                    signature[ptr] = (byte)((aux[e][col] & 0xff) >> offPtr);
                    col++;
                    signature[ptr] |= (byte)((aux[e][col] & 0xff) << (8 - offPtr));
                }
                if (offPtr <= onCol1)
                {
                    ptr++;
                    signature[ptr] = (byte)((aux[e][col] & 0xff) >> offPtr);
                }
                offPtr = 8 - ((onCol1 - offPtr) & 7);
                col++;
            }

            // Process (N-R) columns (R x (N-R) matrix)
            for (int j = 0; j < n - r; j++)
            {
                signature[ptr] |= (aux[e][col] & 0xff) << (8 - offPtr);
                for (int i = 0; i < nRowsBytes2 - 1; ++i)
                {
                    ptr++;
                    signature[ptr] = (byte)((aux[e][col] & 0xff) >> offPtr);
                    col++;
                    signature[ptr] |= (byte)((aux[e][col] & 0xff) << (8 - offPtr));
                }
                if (offPtr <= onCol2)
                {
                    ptr++;
                    signature[ptr] = (byte)((aux[e][col] & 0xff) >> offPtr);
                }
                offPtr = 8 - ((onCol2 - offPtr) & 7);
                col++;
            }

            // Process midAlpha (GF256 elements)
            for (int i = 0; i < rho; i++)
            {
                byte entry = midAlpha[e][i];
                int shift = 8 - offPtr;
                signature[ptr] |= (byte)((entry & 0xff) << shift);
                ptr++;

                if (offPtr < 8)
                {
                    signature[ptr] = (byte)((entry & 0xff) >>> offPtr);
                }
            }
        }
    }

    public void unparseSignature(byte[] signature,
                                 byte[] salt,
                                 long ctr,
                                 byte[] hash2,
                                 byte[][] path,
                                 byte[][] commitsIStar,
                                 byte[][] aux,
                                 short[][] midAlpha)
    {

        int ptr = 0;

        // Copy salt
        System.arraycopy(salt, 0, signature, ptr, saltBytes);
        ptr += saltBytes;

        // Copy counter (little-endian)
        byte[] ctrBytes = Pack.longToLittleEndian(ctr);
        System.arraycopy(ctrBytes, 0, signature, ptr, 8);
        ptr += 8;

        // Copy hash2
        System.arraycopy(hash2, 0, signature, ptr, 2 * securityBytes);
        ptr += 2 * securityBytes;

        // Copy path
        for (int i = 0; i < tOpen; ++i)
        {
            System.arraycopy(path[i], 0, signature, ptr, securityBytes);
            ptr += securityBytes;
        }

        // Copy commits_i_star
        for (byte[] commit : commitsIStar)
        {
            System.arraycopy(commit, 0, signature, ptr, 2 * securityBytes);
            ptr += 2 * securityBytes;
        }

        // Pack field elements
        int offPtr = 8; // Tracks bits remaining in current byte
        int nRowsBytes1 = mirathMatrixFFBytesSize(m, 1); // Bytes per column for M rows
        int nRowsBytes2 = mirathMatrixFFBytesSize(r, 1); // Bytes per column for R rows
        int onCol1, onCol2;
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

        for (int e = 0; e < tau; e++)
        {
            int col = 0;
            // Process R columns (M x R matrix)
            for (int j = 0; j < r; j++)
            {
                signature[ptr] |= (aux[e][col] & 0xff) << (8 - offPtr);
                for (int i = 0; i < nRowsBytes1 - 1; ++i)
                {
                    ptr++;
                    signature[ptr] = (byte)((aux[e][col] & 0xff) >>> offPtr);
                    col++;
                    signature[ptr] |= (byte)((aux[e][col] & 0xff) << (8 - offPtr));
                }
                if (offPtr <= onCol1)
                {
                    ptr++;
                    signature[ptr] = (byte)((aux[e][col] & 0xff) >>> offPtr);
                }
                offPtr = 8 - ((onCol1 - offPtr) & 7);
                col++;
            }

            // Process (N-R) columns (R x (N-R) matrix)
            for (int j = 0; j < n - r; j++)
            {
                signature[ptr] |= (aux[e][col] & 0xff) << (8 - offPtr);
                for (int i = 0; i < nRowsBytes2 - 1; ++i)
                {
                    ptr++;
                    signature[ptr] = (byte)((aux[e][col] & 0xff) >>> offPtr);
                    col++;
                    signature[ptr] |= (byte)((aux[e][col] & 0xff) << (8 - offPtr));
                }
                if (offPtr <= onCol2)
                {
                    ptr++;
                    signature[ptr] = (byte)((aux[e][col] & 0xff) >>> offPtr);
                }
                offPtr = 8 - ((onCol2 - offPtr) & 7);
                col++;
            }

            int onMu = 4;
            short maskHighMu = 0x0F00;
            // Process midAlpha (GF256 elements)
            for (int i = 0; i < rho; i++)
            {
                short entry = midAlpha[e][i];
                int shift = 8 - offPtr;
                byte entryLow = (byte)(entry & 0x00ff);
                byte entryHigh = (byte)((entry & maskHighMu) >>> 8);
                signature[ptr] |= (byte)((entryLow & 0xff) << shift);
                ptr++;
                signature[ptr] = (byte)((entryLow & 0xff) >>> offPtr);
                signature[ptr] |= (byte)((entryHigh & 0xff) << shift);
                if (offPtr > onMu)
                {
                    offPtr = offPtr - onMu;
                }
                else if (offPtr == onMu)
                {
                    ptr++;
                    signature[ptr] = 0;
                    offPtr = 8;
                }
                else
                {
                    ptr++;
                    signature[ptr] = (byte)((entryHigh & 0xff) >> offPtr);
                    offPtr = offPtr + 8 - onMu;
                }
            }
        }
    }

    public int parseSignature(
        byte[] salt,
        long[] ctr,
        byte[] hash2,
        byte[][] path,
        byte[][] commitsIStar,
        byte[][] aux,
        byte[][] midAlpha,
        byte[] signature)
    {
        // Check for trivial forgery
        int tmpBits = (m * r + r * (n - r) + rho * mu) * tau;
        tmpBits *= 4;
        int modBits = tmpBits % 8;
        if (modBits != 0)
        {
            int mask = (1 << modBits) - 1;
            int lastByte = signature[signature.length - 1] & 0xFF;
            if ((lastByte & ~mask) != 0)
            {
                return 1;
            }
        }

        int ptr = 0;

        // Copy salt
        System.arraycopy(signature, ptr, salt, 0, saltBytes);
        ptr += saltBytes;

        // Copy counter (little-endian)
        byte[] ctrBytes = new byte[8];
        System.arraycopy(signature, ptr, ctrBytes, 0, 8);
        ctr[0] = Pack.littleEndianToLong(ctrBytes, 0);
        ptr += 8;

        // Copy hash2
        System.arraycopy(signature, ptr, hash2, 0, 2 * securityBytes);
        ptr += 2 * securityBytes;

        // Copy path
        for (int i = 0; i < tOpen; i++)
        {
            System.arraycopy(signature, ptr, path[i], 0, securityBytes);
            ptr += securityBytes;
        }

        // Copy commits_i_star
        for (int e = 0; e < tau; e++)
        {
            System.arraycopy(signature, ptr, commitsIStar[e], 0, 2 * securityBytes);
            ptr += 2 * securityBytes;
        }

        // Unpack field elements
        int offPtr = 8; // Bits remaining in current byte
        int nRowsBytes1 = mirathMatrixFFBytesSize(m, 4);
        int nRowsBytes2 = mirathMatrixFFBytesSize(r, 4);
        int onCol1 = 8 - ((8 * nRowsBytes1) - (4 * m));
        int onCol2 = 8 - ((8 * nRowsBytes2) - (4 * r));

        for (int e = 0; e < tau; e++)
        {
            int auxIndex = 0;

            // Process R columns (M entries each)
            for (int j = 0; j < r; j++)
            {
                int currentByte = ptr;
                int currentBit = 8 - offPtr;

                for (int i = 0; i < m; i++)
                {
                    int value = 0;
                    for (int b = 0; b < 4; b++)
                    {
                        if (currentBit >= 8)
                        {
                            currentByte++;
                            currentBit = 0;
                        }
                        int bit = (signature[currentByte] >> (7 - currentBit)) & 1;
                        value = (value << 1) | bit;
                        currentBit++;
                    }
                    aux[e][auxIndex++] = (byte)value;
                }

                ptr = currentByte;
                offPtr = 8 - currentBit;
                offPtr = (8 - ((onCol1 - offPtr) % 8)) % 8;
            }

            // Process (N - R) columns (R entries each)
            for (int j = 0; j < (n - r); j++)
            {
                int currentByte = ptr;
                int currentBit = 8 - offPtr;

                for (int i = 0; i < r; i++)
                {
                    int value = 0;
                    for (int b = 0; b < 4; b++)
                    {
                        if (currentBit >= 8)
                        {
                            currentByte++;
                            currentBit = 0;
                        }
                        int bit = (signature[currentByte] >> (7 - currentBit)) & 1;
                        value = (value << 1) | bit;
                        currentBit++;
                    }
                    aux[e][auxIndex++] = (byte)value;
                }

                ptr = currentByte;
                offPtr = 8 - currentBit;
                offPtr = (8 - ((onCol2 - offPtr) % 8)) % 8;
            }

            // Process mid_alpha entries
            for (int i = 0; i < rho; i++)
            {
                int entry;
                if (offPtr == 8)
                {
                    entry = signature[ptr] & 0xFF;
                    ptr++;
                }
                else
                {
                    entry = ((signature[ptr] & 0xFF) << (8 - offPtr));
                    ptr++;
                    entry |= ((signature[ptr] & 0xFF) >>> offPtr);
                }
                midAlpha[e][i] = (byte)entry;
            }
        }
        return 0;
    }

    public void mirathMatrixDecompressPK(byte[] H, byte[] y, byte[] pk)
    {
        SHAKEDigest prng = new SHAKEDigest(128);
        byte[] seedPk = new byte[securityBytes];

        parsePublicKey(seedPk, y, pk);
        mirathPrngInit(prng, null, seedPk, securityBytes);
        int hBytes = calculateMatrixBytes(m * m - k, k);
        prng.doFinal(H, 0, hBytes);
        mirathMatrixSetToFF(H, m * n - k, k);
    }

    private void parsePublicKey(byte[] seedPk, byte[] y, byte[] pk)
    {
        System.arraycopy(pk, 0, seedPk, 0, securityBytes);
        System.arraycopy(pk, securityBytes, y, 0, ffYBytes);
    }

    public int computeParallelShares(byte[][] S_share,
                                     byte[][] C_share,
                                     byte[][] v_share,
                                     int[] iStar,
                                     byte[] hSh,
                                     long ctr,
                                     byte[][] path,
                                     byte[][] commitsIStar,
                                     byte[][] aux,
                                     byte[] salt,
                                     byte[] binding)
    {
        int ret = 0;
        byte[] vGrinding = new byte[securityBytes]; // Adjust size if needed
        byte[] shakeInput = new byte[2 * securityBytes + 8];

        // Prepare SHAKE input
        System.arraycopy(binding, 0, shakeInput, 0, 2 * securityBytes);
        byte[] ctrBytes = Pack.longToLittleEndian(ctr);
        System.arraycopy(ctrBytes, 0, shakeInput, 2 * securityBytes, 8);

        // Expand view challenge
        expandViewChallenge(iStar, vGrinding, shakeInput);

        // Reconstruct commitments
        byte[] hCom = new byte[2 * securityBytes];
        byte[][] seeds = new byte[tau][securityBytes];
        byte[][] tree = new byte[tau][]; // Initialize based on your tree structure
        byte[][][] commits = new byte[tau][][]; // Initialize based on your commit structure

        ret = multivcReconstruct(hCom, seeds, iStar, path, commitsIStar, salt, tree, commits);

        // Hash sh
        mirathTcithHashSh(hSh, salt, hCom, aux);

        // Process each share
        for (int e = 0; e < tau; e++)
        {
            Arrays.fill(S_share[e], (byte)0);
            Arrays.fill(C_share[e], (byte)0);
            Arrays.fill(v_share[e], (byte)0);

            // To be implemented later
            computeShare(S_share[e], C_share[e], v_share[e], iStar[e], seeds, e, aux[e], salt);
        }

        return ret & (discardInputChallenge2(vGrinding) == 0 ? 0 : 1);
    }

    private int multivcReconstruct(byte[] hCom,
                                   byte[][] seeds,
                                   int[] iStar,
                                   byte[][] path,
                                   byte[][] commitsIStar,
                                   byte[] salt,
                                   byte[][] tree,
                                   byte[][][] commits)
    {
        int[] psiIStar = new int[tau];
        for (int e = 0; e < tau; e++)
        {
            psiIStar[e] = mirathTcithPsi(iStar[e], e);
        }

        int pathLength = getSiblingPath(path, tree, psiIStar);
        if (pathLength < 0)
        {
            return -1;
        }

        mirathMultivcCommit(seeds, hCom, tree, commits, salt, new byte[securityBytes]);

        for (int e = 0; e < tau; e++)
        {
            System.arraycopy(commitsIStar[e], 0, commits[e][iStar[e]], 0, 2 * securityBytes);
        }

        return 0;
    }

    private void mirathTcithHashSh(byte[] hSh,
                                   byte[] salt,
                                   byte[] hCom,
                                   byte[][] aux)
    {
        SHAKEDigest digest = new SHAKEDigest(256);
        digest.update((byte)domainSeparatorHash1);
        digest.update(salt, 0, salt.length);
        digest.update(hCom, 0, hCom.length);

        for (byte[] auxEntry : aux)
        {
            digest.update(auxEntry, 0, auxEntry.length);
        }

        digest.doFinal(hSh, 0, 2 * securityBytes);
    }


    private void computeShare(byte[] S_share,
                              byte[] C_share,
                              byte[] v_share,
                              int i_star,
                              byte[][] seeds,
                              int e,
                              byte[] aux,
                              byte[] salt)
    {
        // Split aux into S and C components
        byte[] aux_S = Arrays.copyOfRange(aux, 0, ffSBytes);
        byte[] aux_C = Arrays.copyOfRange(aux, ffSBytes, ffSBytes + ffCBytes);

        // Determine matrix dimensions based on parameter version
        int N = (e < tau1) ? n1 : n2;

        for (int i = 0; i < N; i++)
        {
            if (i != i_star)
            {
                // Calculate index using provided psi function
                int idx = mirathTcithPsi(i, e);

                // Generate cryptographic material
                byte[] sample = new byte[2 * blockLength * securityBytes];
                mirathExpandShare(sample, salt, seeds[idx]);

                // Extract components from sample
                byte[] Si = Arrays.copyOfRange(sample, 0, ffSBytes);
                byte[] Ci = Arrays.copyOfRange(sample, ffSBytes,
                    ffSBytes + ffCBytes);
                byte[] vi = Arrays.copyOfRange(sample, ffSBytes + ffCBytes,
                    ffSBytes + ffCBytes + rho);

                // Apply field constraints
                mirathMatrixSetToFF(Si, m, r);
                mirathMatrixSetToFF(Ci, r, n - r);

                // Calculate scaling factor (XOR in GF(2^8))
                byte sc = (byte)(i_star ^ i);

                // Add scaled components to shares
                mirathMatrixFFMuAddMultipleFF(S_share, sc, Si, m, r);
                mirathMatrixFFMuAddMultipleFF(C_share, sc, Ci, r, n - r);
                mirathVectorFFMuAddMultiple(v_share, v_share, sc, vi, rho);
            }
        }

        // Add final scaled auxiliary components
        byte phi_i = (byte)i_star;
        mirathMatrixFFMuAddMultipleFF(S_share, phi_i, aux_S, m, r);
        mirathMatrixFFMuAddMultipleFF(C_share, phi_i, aux_C, r, n - r);
    }

    public void emulatePartyMu(byte[] baseAlpha,
                               int p,
                               byte[] S_share,
                               byte[] C_share,
                               byte[] v_share,
                               byte[] gamma,
                               byte[] H,
                               byte[] y,
                               byte[] midAlpha) {
        // Initialize temporary buffers
        byte[] e_A = new byte[eA];
        byte[] e_B = new byte[k];
        byte[] aux = new byte[baseMid];
        byte[] Ts = new byte[s];

        // p * S_share (accumulated in Ts)
        mirathMatrixFFMuAddMultiple2(Ts, (byte)p, S_share, m, r);

        // S_share * C_share -> aux
        matrixFFMuProduct(aux, S_share, C_share, m, r, n - r);

        // Split into e_A/e_B
        splitCodewordFFMu(e_A, e_B, Ts, aux);

        // H * e_B -> tmp
        byte[] tmp = new byte[m * n - k];
        matrixFFMuProductFF1Mu(tmp, H, e_B, m * n - k, k, 1);

        // e_A + (H * e_B)
        vectorFFMuAdd(tmp, tmp, e_A, eA);

        // - y * p² (equivalent to XOR in GF)
        byte pSquared = ffMuMult((byte)p, (byte)p);
        mirathVectorFFMuAddMultipleFF(tmp, tmp, pSquared, y, m * n - k);

        // gamma * tmp -> baseAlpha
        matrixFFMuProduct(baseAlpha, gamma, tmp, rho, m * n - k, 1);

        // Add v_share
        vectorFFMuAdd(baseAlpha, baseAlpha, v_share, rho);

        // Add mid_alpha * p
        mirathVectorFFMuAddMultiple(baseAlpha, baseAlpha, (byte)p, midAlpha, rho);
    }

    public void mirathMatrixFFMuAddMultiple2(byte[] matrix, byte scalar, byte[] src,
                                              int nRows, int nCols)
    {
        for (int i = 0; i < nRows; i++)
        {
            for (int j = 0; j < nCols; j++)
            {
                byte entry1 = mirathMatrixFFMuGetEntry(matrix, nRows, i, j);
                byte entry2 = mirathMatrixFFGetEntry(src, nRows, i, j);
                byte product = mirathFFMuMult(scalar, entry2);
                mirathMatrixFFMuSetEntry(matrix, nRows, i, j, (byte)(entry1 ^ product));
            }
        }
    }
}
