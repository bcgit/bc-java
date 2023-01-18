package org.bouncycastle.mls.codec;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface MLSField {
    // Java reflection does not guarantee retrieval in declaration order, so we need to specify it in an annotation
    int order();

    // Java arrays do not have a fixed size set at compile time, so we need to specify.
    int length() default 0;

    boolean optional() default false;
}
