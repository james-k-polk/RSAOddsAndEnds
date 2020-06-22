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

import java.security.SecureRandomSpi;
import java.util.Date;
import java.util.Random;

public class InsecureRandomSpi extends SecureRandomSpi {

    private final Random random;

    InsecureRandomSpi(long seed) {
        this.random = new Random(new Date().getTime());
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
        // does nothing
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        random.nextBytes(bytes);
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        byte [] seed = new byte[numBytes];
        engineNextBytes(seed);
        return seed;
    }
}
