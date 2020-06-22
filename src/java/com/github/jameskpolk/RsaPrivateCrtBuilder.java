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


import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Build a full RSAPrivateCrtKey from partial information, if possible.
 * Only works for RSA moduli that are the product of two distinct odd
 * primes.
 */
public class RsaPrivateCrtBuilder {

    private Optional<List<Long>> smallFactor(long n) {
        List<Long> factors = new ArrayList<>();
        int count = 0;
        if ((n % 2 == 0) || (n == 3)) {
            return null;
        }

        int stop = (int) ((Math.sqrt(n) + 1) / 6.0);

        for (int t = 1; t < stop && factors.size() < 2; t++) {
            for (int plusMinus = 0; plusMinus <= 1; plusMinus++) {
                long p = 6 * t + (1 - 2 * plusMinus);
                if ((n % p) == 0) {
                    factors.add(p);
                    n /= p;
                    if ((n % p) == 0) {
                        return Optional.empty();
                    }
                    stop = (int) ((Math.sqrt(n) + 1) / 6.0);
                }
            }
        }
        if (n > 1) {
            factors.add(n);
            n = 1;
        }
        if (factors.size() == 2) {
            return Optional.empty();
        } else {
            return Optional.of(factors);
        }
    }

    public RSAPrivateCrtKey build() throws InvalidKeyException {


        return null;
    }
}
