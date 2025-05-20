package org.bouncycastle.pqc.crypto.mirath;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.GF16;

class MirathEngine
{
    final int securityBytes;
    final int m;
    final int r;
    final int k;
    final int rho;
    final boolean isA;
    final int ffYBytes;
    final int ffSBytes;
    final int ffCBytes;
    final int ffHBytes;
    /**
     * m * m - k
     */
    final int eA;
    private final int offEA;
    private final int offEB;
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
        m = parameters.getM();
        r = parameters.getR();
        rho = parameters.getRho();
        k = parameters.getK();
        isA = parameters.isA();
        eA = m * m - k;
        ffYBytes = mirathMatrixFFBytesSize(eA, 1);
        ffSBytes = mirathMatrixFFBytesSize(m, r);
        ffCBytes = mirathMatrixFFBytesSize(r, m - r);
        ffHBytes = mirathMatrixFFBytesSize(eA, k);
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

    public void mirathMatrixComputeY(byte[] y, byte[] S, byte[] C, byte[] H, byte[] T)
    {
        int eBSize = mirathMatrixFFBytesSize(k, 1);
        byte[] eA = new byte[ffYBytes];
        byte[] eB = new byte[eBSize];

        // Calculate intermediate matrices
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
            int eightMinusOffEA = 8 - offEA;
            int ffYBytesMinus1 = ffYBytes - 1;
            byte mask = (byte)((1 << eightMinusOffEA) - 1);
            eA[ffYBytesMinus1] = (byte)(E[ffYBytesMinus1] & mask);

            for (int i = 0; i < eBSize - 1; i++)
            {
                eB[i] = (byte)(((E[ffYBytesMinus1 + i] & 0xFF) >>> eightMinusOffEA) ^ ((E[ffYBytes + i] & 0xFF) << offEA));
            }

            if ((offEA + offEB) >= 8)
            {
                eB[eBSize - 1] = (byte)((E[E.length - 1] & 0xFF) >>> eightMinusOffEA);
            }
            else
            {
                eB[eBSize - 1] = (byte)(((E[E.length - 2] & 0xFF) >>> eightMinusOffEA) ^ ((E[E.length - 1] & 0xFF) << offEA));
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
        int eightMinusOffPtr = 8 - offPtr;
        output[ptr] |= (input[col] << eightMinusOffPtr);
        for (int i = 0; i < nRowsBytes - 1; i++)
        {
            output[++ptr] = (byte)((input[col++] & 0xFF) >>> offPtr);
            output[ptr] |= (byte)((input[col] & 0xff) << eightMinusOffPtr);
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
        for (int i = 0, idx = matrixHeight - 1; i < nCols; i++, idx += matrixHeight)
        {
            matrix[idx] &= mask;
        }
    }

    private void mirathMatrixSetToFF(byte[] matrix, int off, int nRows, int nCols, byte mask)
    {
        int matrixHeight = mirathMatrixFfBytesPerColumn(nRows);
        for (int i = 0, idx = matrixHeight - 1 + off; i < nCols; i++, idx += matrixHeight)
        {
            matrix[idx] &= mask;
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

    byte mirathFFMuMult(byte a, byte b)
    {
        int idx = (b & 0xff) << 3;
        byte tmp = 0;

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

    public void matrixFFMuAddMultipleFF(byte[] matrix, byte scalar, byte[] src, int nRows, int nCols)
    {
        if (isA)
        {
            int mult = ((nRows + 1) >>> 1);
            for (int i = 0; i < nRows; i++)
            {
                for (int j = 0, pos = i >>> 1, idx = i; j < nCols; j++, pos += mult, idx += nRows)
                {
                    byte entry = (byte)((i & 1) != 0 ? (src[pos] >>> 4) & 0x0F : src[pos] & 0x0F);
                    matrix[idx] ^= mirathFFMuMult(scalar, MIRATH_MAP_FF_TO_FF_MU[entry]);
                }
            }
        }
        else
        {
            int mult = (nRows + 7) >>> 3;
            for (int i = 0; i < nRows; i++)
            {
                int shift = i & 7;
                for (int j = 0, pos = i >>> 3, idx = i; j < nCols; j++, pos += mult, idx += nRows)
                {
                    matrix[idx] ^= mirathFFMuMult(scalar, (byte)((src[pos] >>> shift) & 0x01));
                }
            }
        }
    }

    public void matrixFFMuAddMultipleFF(byte[] matrix, byte scalar, byte[] src, int off, int nRows, int nCols)
    {
        if (isA)
        {
            int mult = ((nRows + 1) >>> 1);
            for (int i = 0; i < nRows; i++)
            {
                for (int j = 0, pos = (i >>> 1) + off, idx = i; j < nCols; j++, pos += mult, idx += nRows)
                {
                    matrix[idx] ^= mirathFFMuMult(scalar, MIRATH_MAP_FF_TO_FF_MU[((i & 1) != 0 ? (src[pos] >>> 4) & 0x0F : src[pos] & 0x0F)]);
                }
            }
        }
        else
        {
            int mult = (nRows + 7) >>> 3;
            for (int i = 0; i < nRows; i++)
            {
                int shift = i & 7;
                for (int j = 0, pos = off + (i >>> 3), idx = i; j < nCols; j++, pos += mult, idx += nRows)
                {
                    matrix[idx] ^= mirathFFMuMult(scalar, (byte)((src[pos] >>> shift) & 0x01));
                }
            }
        }
    }

    void matrixFFMuAddMu1FFTo(byte[] matrix1, byte[] matrix3, int nRows, int cols)
    {
        if (isA)
        {
            int mult = ((nRows + 1) >>> 1);
            for (int i = 0; i < nRows; i++)
            {
                for (int j = 0, pos = i >>> 1, idx = i; j < cols; j++, pos += mult, idx += nRows)
                {
                    matrix1[idx] ^= MIRATH_MAP_FF_TO_FF_MU[((i & 1) != 0 ? (matrix3[pos] >>> 4) & 0x0F : matrix3[pos] & 0x0F)];
                }
            }
        }
        else
        {
            int mult = (nRows + 7) >>> 3;
            for (int i = 0; i < nRows; i++)
            {
                int shift = i & 7;
                for (int j = 0, pos = i >>> 3, idx = i; j < cols; j++, pos += mult, idx += nRows)
                {
                    matrix1[idx] ^= (matrix3[pos] >>> shift) & 0x01;
                }
            }
        }
    }

    void matrixFFMuAddMu1FFTo(short[] matrix1, byte[] matrix3, int nRows, int cols)
    {
        if (isA)
        {
            int mult = ((nRows + 1) >>> 1);
            for (int i = 0; i < nRows; i++)
            {
                for (int j = 0, pos = i >>> 1, idx = i; j < cols; j++, pos += mult, idx += nRows)
                {
                    matrix1[idx] ^= ((i & 1) != 0 ? (matrix3[pos] >>> 4) & 0x0F : matrix3[pos] & 0x0F);
                }
            }
        }
        else
        {
            int mult = (nRows + 7) >>> 3;
            for (int i = 0; i < nRows; i++)
            {
                int shift = i & 7;
                for (int j = 0, pos = i >>> 3, idx = i; j < cols; j++, pos += mult, idx += nRows)
                {
                    matrix1[idx] ^= (matrix3[pos] >>> shift) & 0x01;
                }
            }
        }
    }

    public void matrixFFMuAddMultipleFF(short[] matrix, short scalar, byte[] src)
    {
        if (isA)
        {
            int mult = ((m + 1) >>> 1);
            for (int i = 0; i < m; i++)
            {
                for (int j = 0, idx = i, pos = (i >>> 1); j < r; j++, idx += m, pos += mult)
                {
                    matrix[idx] ^= mirathFFMuMult(scalar, (byte)((i & 1) != 0 ? (src[pos] >>> 4) & 0x0F : src[pos] & 0x0F));
                }
            }
        }
        else
        {
            int mult = ((m + 7) >>> 3);
            for (int i = 0; i < m; i++)
            {
                int shift = i & 7;
                for (int j = 0, idx = i, pos = i >>> 3; j < r; j++, idx += m, pos += mult)
                {
                    matrix[idx] ^= mirathFFMuMult(scalar, (byte)((src[pos] >>> shift) & 0x01));
                }
            }
        }
    }

    public void matrixFFMuAddMultipleFF(short[] matrix, short scalar, byte[] src, int off)
    {
        if (isA)
        {
            int mult = ((r + 1) >>> 1);
            for (int i = 0; i < r; i++)
            {
                for (int j = 0, pos = (i >>> 1) + off, idx = i; j < m - r; j++, pos += mult, idx += r)
                {
                    matrix[idx] ^= mirathFFMuMult(scalar, (byte)((i & 1) != 0 ? (src[pos] >>> 4) & 0x0F : src[pos] & 0x0F));
                }
            }
        }
        else
        {
            int mult = (r + 7) >>> 3;
            for (int i = 0; i < r; i++)
            {
                int shift = i & 7;
                for (int j = 0, pos = off + (i >>> 3), idx = i; j < m - r; j++, pos += mult, idx += r)
                {
                    matrix[idx] ^= mirathFFMuMult(scalar, (byte)((src[pos] >>> shift) & 0x01));
                }
            }
        }
    }

    public void mirathVectorFFMuAddMultiple(byte[] vector1, byte scalar, byte[] vector3, int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            vector1[i] ^= mirathFFMuMult(scalar, vector3[i]);
        }
    }

    public void mirathVectorFFMuAddMultiple(byte[] vector1, byte scalar, byte[] vector3, int off, int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
            vector1[i] ^= mirathFFMuMult(scalar, vector3[off + i]);
        }
    }

    public void mirathVectorFFMuAddMultiple(short[] vector1, short scalar, short[] vector3, int ncols)
    {
        for (int i = 0; i < ncols; i++)
        {
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
        if (isA)
        {
            int multR = ((nRows1 + 1) >>> 1), multC = ((nCols1 + 1) >>> 1);
            for (int i = 0; i < nRows1; i++)
            {
                int shift = (i >>> 1);
                for (int j = 0, resultPos = shift, jMultC = 0; j < nCols2; j++, resultPos += multR, jMultC += multC)
                {
                    byte entry_i_j = 0;
                    for (int k = 0, entry_i_k_pos = shift; k < nCols1; k++, entry_i_k_pos += multR)
                    {
                        byte entry_i_k = (byte)((i & 1) != 0 ? (matrix1[entry_i_k_pos] >>> 4) & 0x0F : matrix1[entry_i_k_pos] & 0x0F);
                        int pos = jMultC + (k >>> 1);
                        byte entry_k_j = (byte)((k & 1) != 0 ? (matrix2[pos] >>> 4) & 0x0F : matrix2[pos] & 0x0F);
                        entry_i_j ^= GF16.mul(entry_i_k, entry_k_j);
                    }
                    if ((i & 1) != 0)
                    {
                        result[resultPos] = (byte)((result[resultPos] & 0x0F) | ((entry_i_j & 0x0F) << 4));
                    }
                    else
                    {
                        result[resultPos] = (byte)((result[resultPos] & 0xF0) | (entry_i_j & 0x0F));
                    }
                }
            }
        }
        else
        {
            int multR = (nRows1 + 7) >>> 3, multC = (nCols1 + 7) >>> 3;
            for (int i = 0; i < nRows1; i++)
            {
                int bitLine = i & 7;
                byte mask = (byte)(0xff ^ (1 << bitLine));
                for (int j = 0, jMultR = i >>> 3, jMultC = 0; j < nCols2; j++, jMultR += multR, jMultC += multC)
                {
                    byte entry_i_j = 0;
                    for (int k = 0, entry_i_k_pos = i >>> 3; k < nCols1; k++, entry_i_k_pos += multR)
                    {
                        entry_i_j ^= GF16.mul((matrix1[entry_i_k_pos] >>> bitLine) & 0x01, (matrix2[jMultC + (k >>> 3)] >>> (k & 7)) & 0x01);
                    }
                    result[jMultR] = (byte)((result[jMultR] & mask) ^ (entry_i_j << bitLine));
                }
            }
        }
    }

    public void matrixFFMuProduct(byte[] result, int off, byte[] matrix1, byte[] matrix2, int nRows1, int nCols1, int nCols2)
    {
        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0, idx = i + off, jc1 = 0; j < nCols2; j++, idx += nRows1, jc1 += nCols1)
            {
                result[idx] = getEntry_i_j(matrix1, matrix2, nRows1, nCols1, i, jc1);
            }
        }
    }

    private byte getEntry_i_j(byte[] matrix1, byte[] matrix2, int nRows1, int nCols1, int i, int jnCols1)
    {
        byte entry_i_j = 0;
        for (int k = 0, kr = i; k < nCols1; k++, kr += nRows1)
        {
            entry_i_j ^= mirathFFMuMult(matrix1[kr], matrix2[jnCols1 + k]);
        }
        return entry_i_j;
    }

    public void matrixFFMuProductTo(byte[] result, byte[] matrix1, byte[] matrix2)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0, jr = 0, jm = i; j < m - r; j++, jr += r, jm += m)
            {
                result[jm] ^= getEntry_i_j(matrix1, matrix2, m, r, i, jr);
            }
        }
    }

    public void matrixFFMuProductXor(byte[] result, byte[] matrix1, byte[] matrix2, byte[] matrix3)
    {
        for (int i = 0; i < rho; i++)
        {
            byte entry_i_j = matrix3[i];
            for (int k = 0, krho = i; k < eA; k++, krho += rho)
            {
                entry_i_j ^= mirathFFMuMult(matrix1[krho], matrix2[k]);
            }
            result[i] = entry_i_j;
        }
    }

    public void matrixFFMuProduct(short[] result, int off, short[] matrix1, short[] matrix2, int nRows1, int nCols1, int nCols2)
    {
        for (int i = 0; i < nRows1; i++)
        {
            for (int j = 0, idx = i + off, jc1 = 0; j < nCols2; j++, idx += nRows1, jc1 += nCols1)
            {
                result[idx] = getEntry_i_j(matrix1, matrix2, nRows1, nCols1, i, jc1);
            }
        }
    }

    public void matrixFFMuProductTo(short[] result, short[] matrix1, short[] matrix2)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0, idx = i, jr = 0; j < m - r; j++, idx += m, jr += r)
            {
                result[idx] ^= getEntry_i_j(matrix1, matrix2, m, r, i, jr);
            }
        }
    }

    private short getEntry_i_j(short[] matrix1, short[] matrix2, int nRows1, int nCols1, int i, int jnCols1)
    {
        short entry_i_j = 0;
        for (int k = 0, knRow1 = i; k < nCols1; k++, knRow1 += nRows1)
        {
            entry_i_j ^= mirathFFMuMult(matrix1[knRow1], matrix2[jnCols1 + k]);
        }
        return entry_i_j;
    }

    public void matrixFFMuProductXor(short[] result, short[] matrix1, short[] matrix2, short[] matrix3)
    {
        for (int i = 0; i < rho; i++)
        {
            short entry_i_j = matrix3[i];
            for (int k = 0, idx = i; k < eA; k++, idx += rho)
            {
                entry_i_j ^= mirathFFMuMult(matrix1[idx], matrix2[k]);
            }
            result[i] = entry_i_j;
        }
    }

    void matrixFFMuProductFF1MuTo(byte[] result, byte[] mat1, int rows1, int cols1)
    {
        if (isA)
        {
            int mult = ((rows1 + 1) >>> 1);
            for (int i = 0; i < rows1; i++)
            {
                byte entry_i_j = 0;
                for (int k = 0, pos = (i >>> 1); k < cols1; k++, pos += mult)
                {
                    entry_i_j ^= mirathFFMuMult(MIRATH_MAP_FF_TO_FF_MU[((i & 1) != 0 ? (mat1[pos] >>> 4) & 0x0F : mat1[pos] & 0x0F)], result[rows1 + k]);
                }
                result[i] ^= entry_i_j;
            }
        }
        else
        {
            int mult = ((rows1 + 7) >>> 3);
            for (int i = 0; i < rows1; i++)
            {
                byte entry_i_j = 0;
                int shift = i & 7;
                for (int k = 0, pos = i >>> 3; k < cols1; k++, pos += mult)
                {
                    entry_i_j ^= mirathFFMuMult((byte)((mat1[pos] >>> shift) & 0x01), result[rows1 + k]);
                }
                result[i] ^= entry_i_j;
            }
        }
    }

    void matrixFFMuProductFF1MuTo(short[] result, byte[] mat1, int rows1, int cols1)
    {
        if (isA)
        {
            int mult = ((rows1 + 1) >>> 1);
            for (int i = 0; i < rows1; i++)
            {
                short entry_i_j = 0;
                for (int k = 0, pos = (i >>> 1); k < cols1; k++, pos += mult)
                {
                    entry_i_j ^= mirathFFMuMult((short)((i & 1) != 0 ? (mat1[pos] >>> 4) & 0x0F : mat1[pos] & 0x0F), result[rows1 + k]);
                }
                result[i] ^= entry_i_j;
            }
        }
        else
        {
            int mult = ((rows1 + 7) >>> 3);
            for (int i = 0; i < rows1; i++)
            {
                short entry_i_j = 0;
                int shift = i & 7;
                for (int k = 0, pos = i >>> 3; k < cols1; k++, pos += mult)
                {
                    entry_i_j ^= mirathFFMuMult((short)((mat1[pos] >>> shift) & 0x01), result[rows1 + k]);
                }
                result[i] ^= entry_i_j;
            }
        }
    }

    void matrixFFMuAddMu1FF(byte[] matrix1, byte[] matrix2, byte[] matrix3, int rows, int cols)
    {
        if (isA)
        {
            int mult = ((rows + 1) >>> 1);
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0, pos = i >>> 1, idx = i; j < cols; j++, pos += mult, idx += rows)
                {
                    matrix1[idx] = (byte)(matrix2[idx] ^ MIRATH_MAP_FF_TO_FF_MU[((i & 1) != 0 ? (matrix3[pos] >>> 4) & 0x0F : matrix3[pos] & 0x0F)]);
                }
            }
        }
        else
        {
            int mult = ((rows + 7) >>> 3);
            for (int i = 0; i < rows; i++)
            {
                int shift = i & 7;
                for (int j = 0, pos = i >>> 3, idx = i; j < cols; j++, pos += mult, idx += rows)
                {
                    matrix1[idx] = (byte)(matrix2[idx] ^ ((matrix3[pos] >>> shift) & 0x01));
                }
            }
        }
    }

    void matrixFFMuAddMu1FF(short[] matrix1, short[] matrix2, byte[] matrix3, int rows, int cols)
    {
        if (isA)
        {
            int mult = ((rows + 1) >>> 1);
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0, pos = i >>> 1, idx = i; j < cols; j++, pos += mult, idx += rows)
                {
                    matrix1[idx] = (short)(matrix2[idx] ^ ((i & 1) != 0 ? (matrix3[pos] >>> 4) & 0x0F : matrix3[pos] & 0x0F));
                }
            }
        }
        else
        {
            int mult = ((rows + 7) >>> 3);
            for (int i = 0; i < rows; i++)
            {
                int shift = i & 7;
                for (int j = 0, pos = i >>> 3, idx = i; j < cols; j++, pos += mult, idx += rows)
                {
                    matrix1[idx] = (short)(matrix2[idx] ^ ((matrix3[pos] >>> shift) & 0x01));
                }
            }
        }
    }

    public void mirathMatrixFFMuAddMultiple2(byte[] matrix, byte scalar, byte[] src)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0, idx = i; j < r; j++, idx += m)
            {
                matrix[idx] = mirathFFMuMult(scalar, src[idx]);
            }
        }
    }

    public void mirathMatrixFFMuAddMultiple2(short[] matrix, short scalar, short[] src)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0, idx = i; j < r; j++, idx += m)
            {
                matrix[idx] = mirathFFMuMult(scalar, src[idx]);
            }
        }
    }
}
