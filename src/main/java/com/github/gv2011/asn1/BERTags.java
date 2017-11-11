package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


public interface BERTags
{
    public static final int BOOLEAN             = 0x01;
    public static final int INTEGER             = 0x02;
    public static final int BIT_STRING          = 0x03;
    public static final int OCTET_STRING        = 0x04;
    public static final int NULL                = 0x05;
    public static final int OBJECT_IDENTIFIER   = 0x06;
    public static final int EXTERNAL            = 0x08;
    public static final int ENUMERATED          = 0x0a;
    public static final int SEQUENCE            = 0x10;
    public static final int SEQUENCE_OF         = 0x10; // for completeness - used to model a SEQUENCE of the same type.
    public static final int SET                 = 0x11;
    public static final int SET_OF              = 0x11; // for completeness - used to model a SET of the same type.


    public static final int NUMERIC_STRING      = 0x12;
    public static final int PRINTABLE_STRING    = 0x13;
    public static final int T61_STRING          = 0x14;
    public static final int VIDEOTEX_STRING     = 0x15;
    public static final int IA5_STRING          = 0x16;
    public static final int UTC_TIME            = 0x17;
    public static final int GENERALIZED_TIME    = 0x18;
    public static final int GRAPHIC_STRING      = 0x19;
    public static final int VISIBLE_STRING      = 0x1a;
    public static final int GENERAL_STRING      = 0x1b;
    public static final int UNIVERSAL_STRING    = 0x1c;
    public static final int BMP_STRING          = 0x1e;
    public static final int UTF8_STRING         = 0x0c;
    
    public static final int CONSTRUCTED         = 0x20;
    public static final int APPLICATION         = 0x40;
    public static final int TAGGED              = 0x80;
}
