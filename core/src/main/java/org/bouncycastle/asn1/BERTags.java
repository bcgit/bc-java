package org.bouncycastle.asn1;

public interface BERTags
{
    public static final int BOOLEAN             = 0x01;
    public static final int INTEGER             = 0x02;
    public static final int BIT_STRING          = 0x03;
    public static final int OCTET_STRING        = 0x04;
    public static final int NULL                = 0x05;
    public static final int OBJECT_IDENTIFIER   = 0x06;
    public static final int EXTERNAL            = 0x08;
    public static final int ENUMERATED          = 0x0a; // decimal 10
    public static final int SEQUENCE            = 0x10; // decimal 16
    public static final int SEQUENCE_OF         = 0x10; // for completeness - used to model a SEQUENCE of the same type.
    public static final int SET                 = 0x11; // decimal 17
    public static final int SET_OF              = 0x11; // for completeness - used to model a SET of the same type.


    public static final int NUMERIC_STRING      = 0x12; // decimal 18
    public static final int PRINTABLE_STRING    = 0x13; // decimal 19
    public static final int T61_STRING          = 0x14; // decimal 20
    public static final int VIDEOTEX_STRING     = 0x15; // decimal 21
    public static final int IA5_STRING          = 0x16; // decimal 22
    public static final int UTC_TIME            = 0x17; // decimal 23
    public static final int GENERALIZED_TIME    = 0x18; // decimal 24
    public static final int GRAPHIC_STRING      = 0x19; // decimal 25
    public static final int VISIBLE_STRING      = 0x1a; // decimal 26
    public static final int GENERAL_STRING      = 0x1b; // decimal 27
    public static final int UNIVERSAL_STRING    = 0x1c; // decimal 28
    public static final int BMP_STRING          = 0x1e; // decimal 30
    public static final int UTF8_STRING         = 0x0c; // decimal 12
    
    public static final int CONSTRUCTED         = 0x20; // decimal 32
    public static final int APPLICATION         = 0x40; // decimal 64
    public static final int TAGGED              = 0x80; // decimal 128
}
