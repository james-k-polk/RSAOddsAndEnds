/*
 * MIT License
 *
 * Copyright (c) 2020. James K Polk
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package com.github.jameskpolk;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

public class RSAKeyEquivalents {
    private final static KeyFactory RSA_KEY_FAC;

    static {
        try {
            RSA_KEY_FAC = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        }
    }

    public static void main(String[] args) throws Exception {
        doSomeTests();
    }

    private static void doSomeTests() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        long randomSeed = new Date().getTime();
        System.out.println("Random seed is: " + randomSeed);
        Random randomForData = new Random(randomSeed + 1);
        InsecureRandom randomForKeyGen = new InsecureRandom(randomSeed);
        final int numTrials = 200;
        final int keysize = 1024;
        kpGen.initialize(keysize, randomForKeyGen);
        // Generate some RSA keypairs and perturb them in ways that should not affect encryption
        // or decryption
        for (int trial = 0; trial < numTrials; trial++) {
            KeyPair keyPair = kpGen.generateKeyPair();
            RSAPrivateCrtKey originalCRTKey = (RSAPrivateCrtKey) keyPair.getPrivate();
            RSAPrivateCrtKey perturbedCRTKey = perturbCRTKey(originalCRTKey, randomForData);
            // verify equality
            if (!rsaPrivateKeyEquals(perturbedCRTKey, originalCRTKey)) {
                System.out.printf("For randomForKeyGen, seed %d, at trial #%d, private crt keys differ",
                        randomSeed, trial);
            }
            if (!functionallyEqual(perturbedCRTKey, originalCRTKey, randomForData)) {
                System.out.printf("For functionallyEqual, seed %d, at trial #%d, crt keys are not functionally equal",
                        randomSeed, trial);
            }
        }
    }

    private static RSAPrivateCrtKey perturbCRTKey(RSAPrivateCrtKey originalCRTKey, Random random) throws InvalidKeySpecException {
        BigInteger p = originalCRTKey.getPrimeP();
        BigInteger q = originalCRTKey.getPrimeQ();
        BigInteger d = originalCRTKey.getPrivateExponent();
        BigInteger dp = originalCRTKey.getPrimeExponentP();
        BigInteger dq = originalCRTKey.getPrimeExponentQ();
        BigInteger lambda = computeCarmichaelLambda(p, q);
        BigInteger newD = d.add(randomMultiple(32, lambda, random));
        BigInteger newDp = dp.add(randomMultiple(32, p.subtract(BigInteger.ONE), random));
        BigInteger newDq = dq.add(randomMultiple(32, q.subtract(BigInteger.ONE), random));
        BigInteger newQInv = p.modInverse(q);

        // use new values and swap p and q

        RSAPrivateCrtKeySpec newKeySpec = new RSAPrivateCrtKeySpec(
                originalCRTKey.getModulus(),
                originalCRTKey.getPublicExponent(),
                newD,
                q,
                p,
                newDq,
                newDp,
                newQInv
        );

        return (RSAPrivateCrtKey) RSA_KEY_FAC.generatePrivate(newKeySpec);
    }

    private static BigInteger randomMultiple(int upper, BigInteger x, Random random) {
        return x.multiply(BigInteger.valueOf(random.nextInt(upper)));
    }

    private static boolean functionallyEqual(RSAPrivateCrtKey perturbedCRTKey,
                                             RSAPrivateCrtKey originalCRTKey,
                                             Random random) throws Exception {

        // encrypt with original, decrypt with perturbed

        byte[] data = new byte[originalCRTKey.getModulus().bitLength() / 8];
        random.nextBytes(data);
        data[0] = 0;
        Cipher cipher1 = Cipher.getInstance("RSA/ECB/NoPadding");
        PublicKey pub = RSA_KEY_FAC.generatePublic(
                new RSAPublicKeySpec(originalCRTKey.getModulus(), originalCRTKey.getPublicExponent())
        );
        cipher1.init(Cipher.ENCRYPT_MODE, pub);
        byte[] encrypted = cipher1.doFinal(data);
        Cipher cipher2 = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher2.init(Cipher.DECRYPT_MODE, perturbedCRTKey);
        byte[] decrypted = cipher2.doFinal(encrypted);
        if (!Arrays.equals(data, decrypted)) {
            return false;
        }

        // encrypt with perturbed, decrypt with original

        cipher1 = Cipher.getInstance("RSA/ECB/NoPadding");
        pub = RSA_KEY_FAC.generatePublic(
                new RSAPublicKeySpec(perturbedCRTKey.getModulus(), perturbedCRTKey.getPublicExponent())
        );
        cipher1.init(Cipher.ENCRYPT_MODE, pub);
        encrypted = cipher1.doFinal(data);
        cipher2 = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher2.init(Cipher.DECRYPT_MODE, originalCRTKey);
        decrypted = cipher2.doFinal(encrypted);
        return Arrays.equals(data, decrypted);
    }

    /**
     * https://stackoverflow.com/questions/43136036/how-to-get-a-rsaprivatecrtkey-from-a-rsaprivatekey
     * answered Mar 31 '17 at 18:16 President James K. Polk
     * Find a factor of n by following the algorithm outlined in Handbook of Applied Cryptography, section
     * 8.2.2(i). See http://cacr.uwaterloo.ca/hac/about/chap8.pdf.
     */

    private static BigInteger findFactor(BigInteger e, BigInteger d, BigInteger n) {
        BigInteger edMinus1 = e.multiply(d).subtract(BigInteger.ONE);
        int s = edMinus1.getLowestSetBit();
        BigInteger t = edMinus1.shiftRight(s);

        for (int aInt = 2; true; aInt++) {
            BigInteger aPow = BigInteger.valueOf(aInt).modPow(t, n);
            for (int i = 1; i <= s; i++) {
                if (aPow.equals(BigInteger.ONE)) {
                    break;
                }
                if (aPow.equals(n.subtract(BigInteger.ONE))) {
                    break;
                }
                BigInteger aPowSquared = aPow.multiply(aPow).mod(n);
                if (aPowSquared.equals(BigInteger.ONE)) {
                    return aPow.subtract(BigInteger.ONE).gcd(n);
                }
                aPow = aPowSquared;
            }
        }
    }

    public static RSAPrivateCrtKey createCrtKey(RSAPublicKey rsaPub, RSAPrivateKey rsaPriv) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger e = rsaPub.getPublicExponent();
        BigInteger d = rsaPriv.getPrivateExponent();
        BigInteger n = rsaPub.getModulus();
        BigInteger p = findFactor(e, d, n);
        BigInteger q = n.divide(p);
        if (p.compareTo(q) > 0) {
            BigInteger t = p;
            p = q;
            q = t;
        }
        BigInteger exp1 = d.mod(p.subtract(BigInteger.ONE));
        BigInteger exp2 = d.mod(q.subtract(BigInteger.ONE));
        BigInteger coeff = q.modInverse(p);
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, exp1, exp2, coeff);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateCrtKey) kf.generatePrivate(keySpec);
    }

//    private static String bytesToHex(byte[] bytes) {
//        StringBuffer result = new StringBuffer();
//        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
//        return result.toString();
//    }

    private static boolean rsaPrivateKeyEqualsOld(RSAPrivateCrtKey k1, RSAPrivateCrtKey k2) {
        boolean result = true;
        result = result && k1.getModulus().equals(k2.getModulus());
        result = result && k1.getPublicExponent().equals(k2.getPublicExponent());
        result = result && k1.getPrivateExponent().equals(k2.getPrivateExponent());
        result = result && k1.getPrimeP().equals(k2.getPrimeP());
        result = result && k1.getPrimeQ().equals(k2.getPrimeQ());
        result = result && k1.getPrimeExponentP().equals(k2.getPrimeExponentP());
        result = result && k1.getPrimeExponentQ().equals(k2.getPrimeExponentQ());
        result = result && k1.getCrtCoefficient().equals(k2.getCrtCoefficient());

        return result;
    }

    public static boolean rsaPrivateKeyEquals(RSAPrivateCrtKey k1, RSAPrivateCrtKey k2) {

        final BigInteger ZERO = BigInteger.ZERO;

        boolean result = isConsistent(k1) && isConsistent(k2);
        result = result && k1.getModulus().equals(k2.getModulus());
        BigInteger lambda = computeCarmichaelLambda(k1.getPrimeP(), k1.getPrimeQ());

        result = result && k1.getPublicExponent().subtract(k2.getPublicExponent()).mod(lambda).equals(ZERO);
        result = result && k1.getPrivateExponent().subtract(k2.getPrivateExponent()).mod(lambda).equals(ZERO);

        return result;
    }

    private static boolean isConsistent(RSAPrivateCrtKey key) {
        final BigInteger ZERO = BigInteger.ZERO;
        final BigInteger ONE = BigInteger.ONE;

        BigInteger n = key.getModulus();
        BigInteger p = key.getPrimeP();
        BigInteger q = key.getPrimeQ();
        BigInteger e = key.getPublicExponent();
        BigInteger d = key.getPrivateExponent();

        boolean result = p.multiply(q).equals(n);
        BigInteger lambda = computeCarmichaelLambda(p, q);
        result = result && e.multiply(d).mod(lambda).equals(ONE);
        result = result && d.subtract(key.getPrimeExponentP()).mod(p.subtract(ONE)).equals(ZERO);
        result = result && d.subtract(key.getPrimeExponentQ()).mod(q.subtract(ONE)).equals(ZERO);
        result = result && q.multiply(key.getCrtCoefficient()).mod(p).equals(ONE);
        return result;
    }

    private static BigInteger computeCarmichaelLambda(BigInteger p, BigInteger q) {
        return lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
    }

    private static BigInteger lcm(BigInteger x, BigInteger y) {
        return x.multiply(y).divide(x.gcd(y));
    }

}