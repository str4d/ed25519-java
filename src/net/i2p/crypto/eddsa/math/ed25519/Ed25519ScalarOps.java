package net.i2p.crypto.eddsa.math.ed25519;

import java.math.BigInteger;
import net.i2p.crypto.eddsa.math.ScalarOps;

public class Ed25519ScalarOps implements ScalarOps {
    private BigInteger load_3(byte[] in, int offset) {
        BigInteger result = new BigInteger(1, new byte[] {in[offset]});
        result = result.or(new BigInteger(1, new byte[] {in[offset+1]}).shiftLeft(8));
        result = result.or(new BigInteger(1, new byte[] {in[offset+2]}).shiftLeft(16));
        return result;
    }

    private BigInteger load_4(byte[] in, int offset) {
        BigInteger result = new BigInteger(1, new byte[] {in[offset]});
        result = result.or(new BigInteger(1, new byte[] {in[offset+1]}).shiftLeft(8));
        result = result.or(new BigInteger(1, new byte[] {in[offset+2]}).shiftLeft(16));
        result = result.or(new BigInteger(1, new byte[] {in[offset+3]}).shiftLeft(24));
        return result;
    }

    /**
     * Input:<br>
     *   s[0]+256*s[1]+...+256^63*s[63] = s<br><br>
     *
     * Output:<br>
     *   s[0]+256*s[1]+...+256^31*s[31] = s mod l<br>
     *   where l = 2^252 + 27742317777372353535851937790883648493.
     */
    public byte[] reduce(byte[] s) {
        BigInteger num = BigInteger.valueOf(2097151);
        long s0 = num.and(load_3(s, 0)).longValue();
        long s1 = num.and(load_4(s, 2).shiftRight(5)).longValue();
        long s2 = num.and(load_3(s, 5).shiftRight(2)).longValue();
        long s3 = num.and(load_4(s, 7).shiftRight(7)).longValue();
        long s4 = num.and(load_4(s, 10).shiftRight(4)).longValue();
        long s5 = num.and(load_3(s, 13).shiftRight(1)).longValue();
        long s6 = num.and(load_4(s, 15).shiftRight(6)).longValue();
        long s7 = num.and(load_3(s, 18).shiftRight(3)).longValue();
        long s8 = num.and(load_3(s, 21)).longValue();
        long s9 = num.and(load_4(s, 23).shiftRight(5)).longValue();
        long s10 = num.and(load_3(s, 26).shiftRight(2)).longValue();
        long s11 = num.and(load_4(s, 28).shiftRight(7)).longValue();
        long s12 = num.and(load_4(s, 31).shiftRight(4)).longValue();
        long s13 = num.and(load_3(s, 34).shiftRight(1)).longValue();
        long s14 = num.and(load_4(s, 36).shiftRight(6)).longValue();
        long s15 = num.and(load_3(s, 39).shiftRight(3)).longValue();
        long s16 = num.and(load_3(s, 42)).longValue();
        long s17 = num.and(load_4(s, 44).shiftRight(5)).longValue();
        long s18 = num.and(load_3(s, 47).shiftRight(2)).longValue();
        long s19 = num.and(load_4(s, 49).shiftRight(7)).longValue();
        long s20 = num.and(load_4(s, 52).shiftRight(4)).longValue();
        long s21 = num.and(load_3(s, 55).shiftRight(1)).longValue();
        long s22 = num.and(load_4(s, 57).shiftRight(6)).longValue();
        long s23 = (load_4(s, 60).shiftRight(3)).longValue();
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;
        long carry10;
        long carry11;
        long carry12;
        long carry13;
        long carry14;
        long carry15;
        long carry16;

        s11 += s23 * 666643;
        s12 += s23 * 470296;
        s13 += s23 * 654183;
        s14 -= s23 * 997805;
        s15 += s23 * 136657;
        s16 -= s23 * 683901;
        s23 = 0;

        s10 += s22 * 666643;
        s11 += s22 * 470296;
        s12 += s22 * 654183;
        s13 -= s22 * 997805;
        s14 += s22 * 136657;
        s15 -= s22 * 683901;
        s22 = 0;

        s9 += s21 * 666643;
        s10 += s21 * 470296;
        s11 += s21 * 654183;
        s12 -= s21 * 997805;
        s13 += s21 * 136657;
        s14 -= s21 * 683901;
        s21 = 0;

        s8 += s20 * 666643;
        s9 += s20 * 470296;
        s10 += s20 * 654183;
        s11 -= s20 * 997805;
        s12 += s20 * 136657;
        s13 -= s20 * 683901;
        s20 = 0;

        s7 += s19 * 666643;
        s8 += s19 * 470296;
        s9 += s19 * 654183;
        s10 -= s19 * 997805;
        s11 += s19 * 136657;
        s12 -= s19 * 683901;
        s19 = 0;

        s6 += s18 * 666643;
        s7 += s18 * 470296;
        s8 += s18 * 654183;
        s9 -= s18 * 997805;
        s10 += s18 * 136657;
        s11 -= s18 * 683901;
        s18 = 0;

        carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
        carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
        carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

        carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
        carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

        s5 += s17 * 666643;
        s6 += s17 * 470296;
        s7 += s17 * 654183;
        s8 -= s17 * 997805;
        s9 += s17 * 136657;
        s10 -= s17 * 683901;
        s17 = 0;

        s4 += s16 * 666643;
        s5 += s16 * 470296;
        s6 += s16 * 654183;
        s7 -= s16 * 997805;
        s8 += s16 * 136657;
        s9 -= s16 * 683901;
        s16 = 0;

        s3 += s15 * 666643;
        s4 += s15 * 470296;
        s5 += s15 * 654183;
        s6 -= s15 * 997805;
        s7 += s15 * 136657;
        s8 -= s15 * 683901;
        s15 = 0;

        s2 += s14 * 666643;
        s3 += s14 * 470296;
        s4 += s14 * 654183;
        s5 -= s14 * 997805;
        s6 += s14 * 136657;
        s7 -= s14 * 683901;
        s14 = 0;

        s1 += s13 * 666643;
        s2 += s13 * 470296;
        s3 += s13 * 654183;
        s4 -= s13 * 997805;
        s5 += s13 * 136657;
        s6 -= s13 * 683901;
        s13 = 0;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        s12 = 0;

        carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

        carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

        byte[] result = new byte[32];
        result[0] = (byte) (s0 >> 0);
        result[1] = (byte) (s0 >> 8);
        result[2] = (byte) ((s0 >> 16) | (s1 << 5));
        result[3] = (byte) (s1 >> 3);
        result[4] = (byte) (s1 >> 11);
        result[5] = (byte) ((s1 >> 19) | (s2 << 2));
        result[6] = (byte) (s2 >> 6);
        result[7] = (byte) ((s2 >> 14) | (s3 << 7));
        result[8] = (byte) (s3 >> 1);
        result[9] = (byte) (s3 >> 9);
        result[10] = (byte) ((s3 >> 17) | (s4 << 4));
        result[11] = (byte) (s4 >> 4);
        result[12] = (byte) (s4 >> 12);
        result[13] = (byte) ((s4 >> 20) | (s5 << 1));
        result[14] = (byte) (s5 >> 7);
        result[15] = (byte) ((s5 >> 15) | (s6 << 6));
        result[16] = (byte) (s6 >> 2);
        result[17] = (byte) (s6 >> 10);
        result[18] = (byte) ((s6 >> 18) | (s7 << 3));
        result[19] = (byte) (s7 >> 5);
        result[20] = (byte) (s7 >> 13);
        result[21] = (byte) (s8 >> 0);
        result[22] = (byte) (s8 >> 8);
        result[23] = (byte) ((s8 >> 16) | (s9 << 5));
        result[24] = (byte) (s9 >> 3);
        result[25] = (byte) (s9 >> 11);
        result[26] = (byte) ((s9 >> 19) | (s10 << 2));
        result[27] = (byte) (s10 >> 6);
        result[28] = (byte) ((s10 >> 14) | (s11 << 7));
        result[29] = (byte) (s11 >> 1);
        result[30] = (byte) (s11 >> 9);
        result[31] = (byte) (s11 >> 17);
        return result;
    }

    public byte[] multiplyAndAdd(byte[] a, byte[] b, byte[] c) {
        // TODO Auto-generated method stub
        return null;
    }
}
