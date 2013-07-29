package org.bouncycastle.asn1;

/**
 * ASN.1 BER/DER encodings use these tag values.
 */
public interface BERTags
{
    /** 0x01 */
    public static final int BOOLEAN             = 0x01;
    /** 0x02 */
    public static final int INTEGER             = 0x02;
    /** 0x03 */
    public static final int BIT_STRING          = 0x03;
    /** 0x04 */
    public static final int OCTET_STRING        = 0x04;
    /** 0x05 */
    public static final int NULL                = 0x05;
    /** 0x06 */
    public static final int OBJECT_IDENTIFIER   = 0x06;
    /** 0x08 */
    public static final int EXTERNAL            = 0x08;
    /** 0x0a = 10 */
    public static final int ENUMERATED          = 0x0a;
    /** 0x10 = 16 */
    public static final int SEQUENCE            = 0x10;
    /** 0x10 = 16 */
    public static final int SEQUENCE_OF         = 0x10; // for completeness
    /** 0x11 = 17 */
    public static final int SET                 = 0x11;
    /** 0x11 = 17 */
    public static final int SET_OF              = 0x11; // for completeness


    /** 0x12 = 18 */
    public static final int NUMERIC_STRING      = 0x12;
    /** 0x13 = 19 */
    public static final int PRINTABLE_STRING    = 0x13;
    /** 0x14 = 20 */
    public static final int T61_STRING          = 0x14;
    /** 0x15 = 21 */
    public static final int VIDEOTEX_STRING     = 0x15;
    /** 0x16 = 22 */
    public static final int IA5_STRING          = 0x16;
    /** 0x17 = 23 */
    public static final int UTC_TIME            = 0x17;
    /** 0x18 = 24 */
    public static final int GENERALIZED_TIME    = 0x18;
    /** 0x19 = 25 */
    public static final int GRAPHIC_STRING      = 0x19;
    /** 0x1a = 26 */
    public static final int VISIBLE_STRING      = 0x1a;
    /** 0x1b = 27 */
    public static final int GENERAL_STRING      = 0x1b;
    /** 0x1c = 28 */
    public static final int UNIVERSAL_STRING    = 0x1c;
    /** 0x1e = 30 */
    public static final int BMP_STRING          = 0x1e;
    /** 0x0c = 12 */
    public static final int UTF8_STRING         = 0x0c;
    
    /** 0x20  */
    public static final int CONSTRUCTED         = 0x20;
    /** 0x40  */
    public static final int APPLICATION         = 0x40;
    /** 0x80  */
    public static final int TAGGED              = 0x80;
}
