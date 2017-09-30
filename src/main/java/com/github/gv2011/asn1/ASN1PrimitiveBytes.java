package com.github.gv2011.asn1;

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
