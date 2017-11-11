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


import com.github.gv2011.util.bytes.Bytes;

public abstract class ASN1PrimitiveBytes extends ASN1Primitive{

  final Bytes string;

  protected ASN1PrimitiveBytes(final Bytes string) {
    this.string = string;
  }

  public final Bytes getOctets()
  {
    return string;
  }

  @Override
  public final int hashCode(){
    return string.hashCode();
  }

  @Override int encodedLength(){
    return StreamUtil.typicalLength(string);
  }

  @Override
  final boolean asn1Equals(final ASN1Primitive o){
    if (!asn1EqualsClass().isInstance(o)) return false;
    else return string.equals(((ASN1PrimitiveBytes)o).string);
  }

  protected Class<? extends ASN1PrimitiveBytes> asn1EqualsClass(){
    return getClass();
  }

}
