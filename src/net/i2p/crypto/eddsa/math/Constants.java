package net.i2p.crypto.eddsa.math;

import java.math.BigInteger;

public class Constants {
    public static final BigInteger ZERO = BigInteger.valueOf(0);
    public static final BigInteger ONE = BigInteger.valueOf(1);
    public static final BigInteger TWO = BigInteger.valueOf(2);
    public static final BigInteger THREE = BigInteger.valueOf(3);
    public static final BigInteger FIVE = BigInteger.valueOf(5);
    public static final FieldElement I = new FieldElement(new BigInteger("19681161376707505956807079304988542015446066515923890162744021073123829784752"));
    public static final BigInteger un = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819967");
}
