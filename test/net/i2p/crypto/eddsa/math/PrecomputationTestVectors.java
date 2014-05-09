package net.i2p.crypto.eddsa.math;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

import net.i2p.crypto.eddsa.TestUtils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

public class PrecomputationTestVectors {
    // Test files were generated using base.py and base2.py from ref10
    // (by printing hex(x%q) instead of the radix-255 representation).
    static GroupElement[][] testPrecmp = getPrecomputation("basePrecmp");
    static GroupElement[] testDblPrecmp = getDoublePrecomputation("baseDblPrecmp");

    public static GroupElement[][] getPrecomputation(String fileName) {
        EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName("ed25519-sha-512");
        Curve curve = ed25519.getCurve();
        GroupElement[][] precmp = new GroupElement[32][8];
        BufferedReader file = null;
        int row = 0, col = 0;
        try {
            file = new BufferedReader(new InputStreamReader(
                    PrecomputationTestVectors.class.getResourceAsStream(fileName)));
            String line;
            while ((line = file.readLine()) != null) {
                if (line.equals(" },"))
                    col += 1;
                else if (line.equals("},")) {
                    col = 0;
                    row += 1;
                } else if (line.startsWith("  { 0x")) {
                    String ypxStr = line.substring(6, line.indexOf('L'));
                    while (ypxStr.length() < 64)
                        ypxStr = "0" + ypxStr;
                    FieldElement ypx = curve.fromBigInteger(new BigInteger(
                            TestUtils.hexToBytes(ypxStr)));
                    line = file.readLine();
                    String ymxStr = line.substring(6, line.indexOf('L'));
                    while (ymxStr.length() < 64)
                        ymxStr = "0" + ymxStr;
                    FieldElement ymx = curve.fromBigInteger(new BigInteger(
                            TestUtils.hexToBytes(ymxStr)));
                    line = file.readLine();
                    String xy2dStr = line.substring(6, line.indexOf('L'));
                    while (xy2dStr.length() < 64)
                        xy2dStr = "0" + xy2dStr;
                    FieldElement xy2d = curve.fromBigInteger(new BigInteger(
                            TestUtils.hexToBytes(xy2dStr)));
                    precmp[row][col] = GroupElement.precomp(curve,
                            ypx, ymx, xy2d);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (file != null) try { file.close(); } catch (IOException e) {}
        }
        return precmp;
    }

    public static GroupElement[] getDoublePrecomputation(String fileName) {
        EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName("ed25519-sha-512");
        Curve curve = ed25519.getCurve();
        GroupElement[] dblPrecmp = new GroupElement[8];
        BufferedReader file = null;
        int row = 0;
        try {
            file = new BufferedReader(new InputStreamReader(
                    PrecomputationTestVectors.class.getResourceAsStream(fileName)));
            String line;
            while ((line = file.readLine()) != null) {
                if (line.equals(" },")) {
                    row += 1;
                } else if (line.startsWith("  { 0x")) {
                    String ypxStr = line.substring(6, line.indexOf('L'));
                    while (ypxStr.length() < 64)
                        ypxStr = "0" + ypxStr;
                    FieldElement ypx = curve.fromBigInteger(new BigInteger(
                            TestUtils.hexToBytes(ypxStr)));
                    line = file.readLine();
                    String ymxStr = line.substring(6, line.indexOf('L'));
                    while (ymxStr.length() < 64)
                        ymxStr = "0" + ymxStr;
                    FieldElement ymx = curve.fromBigInteger(new BigInteger(
                            TestUtils.hexToBytes(ymxStr)));
                    line = file.readLine();
                    String xy2dStr = line.substring(6, line.indexOf('L'));
                    while (xy2dStr.length() < 64)
                        xy2dStr = "0" + xy2dStr;
                    FieldElement xy2d = curve.fromBigInteger(new BigInteger(
                            TestUtils.hexToBytes(xy2dStr)));
                    dblPrecmp[row] = GroupElement.precomp(curve,
                            ypx, ymx, xy2d);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (file != null) try { file.close(); } catch (IOException e) {}
        }
        return dblPrecmp;
    }
}
