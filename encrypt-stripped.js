var jQuery = Object();
! function ($)
{
    $.rsa = $.rsa ||
    {}, $.rsa.encrypt = function (val, nn, ee)
    {
        function BigInteger(a, b, c)
        {
            null != a && ("number" == typeof a ? this.fromNumber(a, b, c) : null == b && "string" != typeof a ? this.fromString(a, 256) : this.fromString(a, b))
        }

        function nbi()
        {
            return new BigInteger(null)
        }

        function int2char(n)
        {
            return BI_RM.charAt(n)
        }

        function intAt(s, i)
        {
            var c = BI_RC[s.charCodeAt(i)];
            return null == c ? -1 : c
        }

        function nbv(i)
        {
            var r = nbi();
            return r.fromInt(i), r
        }

        function nbits(x)
        {
            var t, r = 1;
            return 0 != (t = x >>> 16) && (x = t, r += 16), 0 != (t = x >> 8) && (x = t, r += 8), 0 != (t = x >> 4) && (x = t, r += 4), 0 != (t = x >> 2) && (x = t, r += 2), 0 != (t = x >> 1) && (x = t, r += 1), r
        }

        function Classic(m)
        {
            this.m = m
        }

        function Montgomery(m)
        {
            this.m = m, this.mp = m.invDigit(), this.mpl = 32767 & this.mp, this.mph = this.mp >> 15, this.um = (1 << m.DB - 15) - 1, this.mt2 = 2 * m.t
        }

        function Arcfour()
        {
            this.i = 0, this.j = 0, this.S = new Array
        }

        function prng_newstate()
        {
            return new Arcfour
        }

        function rng_seed_int(x)
        {
            rng_pool[rng_pptr++] ^= 255 & x, rng_pool[rng_pptr++] ^= x >> 8 & 255, rng_pool[rng_pptr++] ^= x >> 16 & 255, rng_pool[rng_pptr++] ^= x >> 24 & 255, rng_pptr >= rng_psize && (rng_pptr -= rng_psize)
        }

        function rng_seed_time()
        {
            rng_seed_int((new Date).getTime())
        }

        function rng_get_byte()
        {
            if (null == rng_state)
            {
                for (rng_seed_time(), (rng_state = prng_newstate()).init(rng_pool), rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr) rng_pool[rng_pptr] = 0;
                rng_pptr = 0
            }
            return rng_state.next()
        }

        function SecureRandom()
        {}

        function parseBigInt(str, r)
        {
            return new BigInteger(str, r)
        }

        function pkcs1pad2(s, n)
        {
            if (n < s.length + 11) return null;
            for (var ba = new Array, i = s.length - 1; i >= 0 && n > 0;)
            {
                var c = s.charCodeAt(i--);
                c < 128 ? ba[--n] = c : c > 127 && c < 2048 ? (ba[--n] = 63 & c | 128, ba[--n] = c >> 6 | 192) : (ba[--n] = 63 & c | 128, ba[--n] = c >> 6 & 63 | 128, ba[--n] = c >> 12 | 224)
            }
            ba[--n] = 0;
            for (var rng = new SecureRandom, x = new Array; n > 2;)
            {
                for (x[0] = 0; 0 == x[0];) rng.nextBytes(x);
                ba[--n] = x[0]
            }
            return ba[--n] = 2, ba[--n] = 0, new BigInteger(ba)
        }

        function RSAKey()
        {
            this.n = null, this.e = 0, this.d = null, this.p = null, this.q = null, this.dmp1 = null, this.dmq1 = null, this.coeff = null
        }
        var dbits;
        /*"Microsoft Internet Explorer" == navigator.appName ? (BigInteger.prototype.am = function (i, x, w, j, c, n)
        {
            for (var xl = 32767 & x, xh = x >> 15; --n >= 0;)
            {
                var l = 32767 & this[i],
                    h = this[i++] >> 15,
                    m = xh * l + h * xl;
                c = ((l = xl * l + ((32767 & m) << 15) + w[j] + (1073741823 & c)) >>> 30) + (m >>> 15) + xh * h + (c >>> 30), w[j++] = 1073741823 & l
            }
            return c
        }, dbits = 30) : "Netscape" != navigator.appName ? (BigInteger.prototype.am = function (i, x, w, j, c, n)
        {
            for (; --n >= 0;)
            {
                var v = x * this[i++] + w[j] + c;
                c = Math.floor(v / 67108864), w[j++] = 67108863 & v
            }
            return c
        }, dbits = 26) :*/ (BigInteger.prototype.am = function (i, x, w, j, c, n)
        {
            for (var xl = 16383 & x, xh = x >> 14;
                --n >= 0;)
            {
                var l = 16383 & this[i],
                    h = this[i++] >> 14,
                    m = xh * l + h * xl;
                c = ((l = xl * l + ((16383 & m) << 14) + w[j] + c) >> 28) + (m >> 14) + xh * h, w[j++] = 268435455 & l
            }
            return c
        }, dbits = 28), BigInteger.prototype.DB = dbits, BigInteger.prototype.DM = (1 << dbits) - 1, BigInteger.prototype.DV = 1 << dbits;
        BigInteger.prototype.FV = Math.pow(2, 52), BigInteger.prototype.F1 = 52 - dbits, BigInteger.prototype.F2 = 2 * dbits - 52;
        var rr, vv, BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz",
            BI_RC = new Array;
        for (rr = "0".charCodeAt(0), vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
        for (rr = "a".charCodeAt(0), vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
        for (rr = "A".charCodeAt(0), vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
        Classic.prototype.convert = function (x)
        {
            return x.s < 0 || x.compareTo(this.m) >= 0 ? x.mod(this.m) : x
        }, Classic.prototype.revert = function (x)
        {
            return x
        }, Classic.prototype.reduce = function (x)
        {
            x.divRemTo(this.m, null, x)
        }, Classic.prototype.mulTo = function (x, y, r)
        {
            x.multiplyTo(y, r), this.reduce(r)
        }, Classic.prototype.sqrTo = function (x, r)
        {
            x.squareTo(r), this.reduce(r)
        }, Montgomery.prototype.convert = function (x)
        {
            var r = nbi();
            return x.abs().dlShiftTo(this.m.t, r), r.divRemTo(this.m, null, r), x.s < 0 && r.compareTo(BigInteger.ZERO) > 0 && this.m.subTo(r, r), r
        }, Montgomery.prototype.revert = function (x)
        {
            var r = nbi();
            return x.copyTo(r), this.reduce(r), r
        }, Montgomery.prototype.reduce = function (x)
        {
            for (; x.t <= this.mt2;) x[x.t++] = 0;
            for (var i = 0; i < this.m.t; ++i)
            {
                var j = 32767 & x[i],
                    u0 = j * this.mpl + ((j * this.mph + (x[i] >> 15) * this.mpl & this.um) << 15) & x.DM;
                for (x[j = i + this.m.t] += this.m.am(0, u0, x, i, 0, this.m.t); x[j] >= x.DV;) x[j] -= x.DV, x[++j]++
            }
            x.clamp(), x.drShiftTo(this.m.t, x), x.compareTo(this.m) >= 0 && x.subTo(this.m, x)
        }, Montgomery.prototype.mulTo = function (x, y, r)
        {
            x.multiplyTo(y, r), this.reduce(r)
        }, Montgomery.prototype.sqrTo = function (x, r)
        {
            x.squareTo(r), this.reduce(r)
        }, BigInteger.prototype.copyTo = function (r)
        {
            for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
            r.t = this.t, r.s = this.s
        }, BigInteger.prototype.fromInt = function (x)
        {
            this.t = 1, this.s = x < 0 ? -1 : 0, x > 0 ? this[0] = x : x < -1 ? this[0] = x + this.DV : this.t = 0
        }, BigInteger.prototype.fromString = function (s, b)
        {
            var k;
            if (16 == b) k = 4;
            else if (8 == b) k = 3;
            else if (256 == b) k = 8;
            else if (2 == b) k = 1;
            else if (32 == b) k = 5;
            else
            {
                if (4 != b) return void this.fromRadix(s, b);
                k = 2
            }
            this.t = 0, this.s = 0;
            for (var i = s.length, mi = !1, sh = 0;
                --i >= 0;)
            {
                var x = 8 == k ? 255 & s[i] : intAt(s, i);
                x < 0 ? "-" == s.charAt(i) && (mi = !0) : (mi = !1, 0 == sh ? this[this.t++] = x : sh + k > this.DB ? (this[this.t - 1] |= (x & (1 << this.DB - sh) - 1) << sh, this[this.t++] = x >> this.DB - sh) : this[this.t - 1] |= x << sh, (sh += k) >= this.DB && (sh -= this.DB))
            }
            8 == k && 0 != (128 & s[0]) && (this.s = -1, sh > 0 && (this[this.t - 1] |= (1 << this.DB - sh) - 1 << sh)), this.clamp(), mi && BigInteger.ZERO.subTo(this, this)
        }, BigInteger.prototype.clamp = function ()
        {
            for (var c = this.s & this.DM; this.t > 0 && this[this.t - 1] == c;) --this.t
        }, BigInteger.prototype.dlShiftTo = function (n, r)
        {
            var i;
            for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
            for (i = n - 1; i >= 0; --i) r[i] = 0;
            r.t = this.t + n, r.s = this.s
        }, BigInteger.prototype.drShiftTo = function (n, r)
        {
            for (var i = n; i < this.t; ++i) r[i - n] = this[i];
            r.t = Math.max(this.t - n, 0), r.s = this.s
        }, BigInteger.prototype.lShiftTo = function (n, r)
        {
            var i, bs = n % this.DB,
                cbs = this.DB - bs,
                bm = (1 << cbs) - 1,
                ds = Math.floor(n / this.DB),
                c = this.s << bs & this.DM;
            for (i = this.t - 1; i >= 0; --i) r[i + ds + 1] = this[i] >> cbs | c, c = (this[i] & bm) << bs;
            for (i = ds - 1; i >= 0; --i) r[i] = 0;
            r[ds] = c, r.t = this.t + ds + 1, r.s = this.s, r.clamp()
        }, BigInteger.prototype.rShiftTo = function (n, r)
        {
            r.s = this.s;
            var ds = Math.floor(n / this.DB);
            if (ds >= this.t) r.t = 0;
            else
            {
                var bs = n % this.DB,
                    cbs = this.DB - bs,
                    bm = (1 << bs) - 1;
                r[0] = this[ds] >> bs;
                for (var i = ds + 1; i < this.t;
                    ++i) r[i - ds - 1] |= (this[i] & bm) << cbs, r[i - ds] = this[i] >> bs;
                bs > 0 && (r[this.t - ds - 1] |= (this.s & bm) << cbs), r.t = this.t - ds, r.clamp()
            }
        }, BigInteger.prototype.subTo = function (a, r)
        {
            for (var i = 0, c = 0, m = Math.min(a.t, this.t); i < m;) c += this[i] - a[i], r[i++] = c & this.DM, c >>= this.DB;
            if (a.t < this.t)
            {
                for (c -= a.s; i < this.t;) c += this[i], r[i++] = c & this.DM, c >>= this.DB;
                c += this.s
            }
            else
            {
                for (c += this.s; i < a.t;) c -= a[i], r[i++] = c & this.DM, c >>= this.DB;
                c -= a.s
            }
            r.s = c < 0 ? -1 : 0, c < -1 ? r[i++] = this.DV + c : c > 0 && (r[i++] = c), r.t = i, r.clamp()
        }, BigInteger.prototype.multiplyTo = function (a, r)
        {
            var x = this.abs(),
                y = a.abs(),
                i = x.t;
            for (r.t = i + y.t; --i >= 0;) r[i] = 0;
            for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
            r.s = 0, r.clamp(), this.s != a.s && BigInteger.ZERO.subTo(r, r)
        }, BigInteger.prototype.squareTo = function (r)
        {
            for (var x = this.abs(), i = r.t = 2 * x.t; --i >= 0;) r[i] = 0;
            for (i = 0; i < x.t - 1; ++i)
            {
                var c = x.am(i, x[i], r, 2 * i, 0, 1);
                (r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV && (r[i + x.t] -= x.DV, r[i + x.t + 1] = 1)
            }
            r.t > 0 && (r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1)), r.s = 0, r.clamp()
        }, BigInteger.prototype.divRemTo = function (m, q, r)
        {
            var pm = m.abs();
            if (!(pm.t <= 0))
            {
                var pt = this.abs();
                if (pt.t < pm.t) return null != q && q.fromInt(0), void(null != r && this.copyTo(r));
                null == r && (r = nbi());
                var y = nbi(),
                    ts = this.s,
                    ms = m.s,
                    nsh = this.DB - nbits(pm[pm.t - 1]);
                nsh > 0 ? (pm.lShiftTo(nsh, y), pt.lShiftTo(nsh, r)) : (pm.copyTo(y), pt.copyTo(r));
                var ys = y.t,
                    y0 = y[ys - 1];
                if (0 != y0)
                {
                    var yt = y0 * (1 << this.F1) + (ys > 1 ? y[ys - 2] >> this.F2 : 0),
                        d1 = this.FV / yt,
                        d2 = (1 << this.F1) / yt,
                        e = 1 << this.F2,
                        i = r.t,
                        j = i - ys,
                        t = null == q ? nbi() : q;
                    for (y.dlShiftTo(j, t), r.compareTo(t) >= 0 && (r[r.t++] = 1, r.subTo(t, r)), BigInteger.ONE.dlShiftTo(ys, t), t.subTo(y, y); y.t < ys;) y[y.t++] = 0;
                    for (; --j >= 0;)
                    {
                        var qd = r[--i] == y0 ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
                        if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd)
                            for (y.dlShiftTo(j, t), r.subTo(t, r); r[i] < --qd;) r.subTo(t, r)
                    }
                    null != q && (r.drShiftTo(ys, q), ts != ms && BigInteger.ZERO.subTo(q, q)), r.t = ys, r.clamp(), nsh > 0 && r.rShiftTo(nsh, r), ts < 0 && BigInteger.ZERO.subTo(r, r)
                }
            }
        }, BigInteger.prototype.invDigit = function ()
        {
            if (this.t < 1) return 0;
            var x = this[0];
            if (0 == (1 & x)) return 0;
            var y = 3 & x;
            return y = y * (2 - (15 & x) * y) & 15, y = y * (2 - (255 & x) * y) & 255, y = y * (2 - ((65535 & x) * y & 65535)) & 65535, (y = y * (2 - x * y % this.DV) % this.DV) > 0 ? this.DV - y : -y
        }, BigInteger.prototype.isEven = function ()
        {
            return 0 == (this.t > 0 ? 1 & this[0] : this.s)
        }, BigInteger.prototype.exp = function (e, z)
        {
            if (e > 4294967295 || e < 1) return BigInteger.ONE;
            var r = nbi(),
                r2 = nbi(),
                g = z.convert(this),
                i = nbits(e) - 1;
            for (g.copyTo(r); --i >= 0;)
                if (z.sqrTo(r, r2), (e & 1 << i) > 0) z.mulTo(r2, g, r);
                else
                {
                    var t = r;
                    r = r2, r2 = t
                }
            return z.revert(r)
        }, BigInteger.prototype.toString = function (b)
        {
            if (this.s < 0) return "-" + this.negate().toString(b);
            var k;
            if (16 == b) k = 4;
            else if (8 == b) k = 3;
            else if (2 == b) k = 1;
            else if (32 == b) k = 5;
            else
            {
                if (4 != b) return this.toRadix(b);
                k = 2
            }
            var d, km = (1 << k) - 1,
                m = !1,
                r = "",
                i = this.t,
                p = this.DB - i * this.DB % k;
            if (i-- > 0)
                for (p < this.DB && (d = this[i] >> p) > 0 && (m = !0, r = int2char(d)); i >= 0;) p < k ? (d = (this[i] & (1 << p) - 1) << k - p, d |= this[--i] >> (p += this.DB - k)) : (d = this[i] >> (p -= k) & km, p <= 0 && (p += this.DB, --i)), d > 0 && (m = !0), m && (r += int2char(d));
            return m ? r : "0"
        }, BigInteger.prototype.negate = function ()
        {
            var r = nbi();
            return BigInteger.ZERO.subTo(this, r), r
        }, BigInteger.prototype.abs = function ()
        {
            return this.s < 0 ? this.negate() : this
        }, BigInteger.prototype.compareTo = function (a)
        {
            var r = this.s - a.s;
            if (0 != r) return r;
            var i = this.t;
            if (0 != (r = i - a.t)) return this.s < 0 ? -r : r;
            for (; --i >= 0;)
                if (0 != (r = this[i] - a[i])) return r;
            return 0
        }, BigInteger.prototype.bitLength = function ()
        {
            return this.t <= 0 ? 0 : this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ this.s & this.DM)
        }, BigInteger.prototype.mod = function (a)
        {
            var r = nbi();
            return this.abs().divRemTo(a, null, r), this.s < 0 && r.compareTo(BigInteger.ZERO) > 0 && a.subTo(r, r), r
        }, BigInteger.prototype.modPowInt = function (e, m)
        {
            var z;
            return z = e < 256 || m.isEven() ? new Classic(m) : new Montgomery(m), this.exp(e, z)
        }, BigInteger.ZERO = nbv(0), BigInteger.ONE = nbv(1), Arcfour.prototype.init = function (key)
        {
            var i, j, t;
            for (i = 0; i < 256; ++i) this.S[i] = i;
            for (j = 0, i = 0; i < 256; ++i) j = j + this.S[i] + key[i % key.length] & 255, t = this.S[i], this.S[i] = this.S[j], this.S[j] = t;
            this.i = 0, this.j = 0
        }, Arcfour.prototype.next = function ()
        {
            var t;
            return this.i = this.i + 1 & 255, this.j = this.j + this.S[this.i] & 255, t = this.S[this.i], this.S[this.i] = this.S[this.j], this.S[this.j] = t, this.S[t + this.S[this.i] & 255]
        };
        var rng_state, rng_pool, rng_pptr, rng_psize = 256;
        if (null == rng_pool)
        {
            rng_pool = new Array, rng_pptr = 0;
            var t;
            /*if (window.crypto && window.crypto.getRandomValues)
            {
                var ua = new Uint8Array(32);
                for (window.crypto.getRandomValues(ua), t = 0; t < 32; ++t) rng_pool[rng_pptr++] = ua[t]
            }*/
            /*if ("Netscape" == navigator.appName && navigator.appVersion < "5" && window.crypto)
            {
                var z = window.crypto.random(32);
                for (t = 0; t < z.length; ++t) rng_pool[rng_pptr++] = 255 & z.charCodeAt(t)
            }*/
            for (; rng_pptr < rng_psize;) t = Math.floor(65536 * Math.random()), rng_pool[rng_pptr++] = t >>> 8, rng_pool[rng_pptr++] = 255 & t;
            rng_pptr = 0, rng_seed_time()
        }
        SecureRandom.prototype.nextBytes = function (ba)
        {
            var i;
            for (i = 0; i < ba.length; ++i) ba[i] = rng_get_byte()
        }, RSAKey.prototype.doPublic = function (x)
        {
            return x.modPowInt(this.e, this.n)
        }, RSAKey.prototype.setPublic = function (N, E)
        {
            null != N && null != E && N.length > 0 && E.length > 0 ? (this.n = parseBigInt(N, 16), this.e = parseInt(E, 16)) : /*alert*/print("Invalid RSA public key")
        }, RSAKey.prototype.encrypt = function (text)
        {
            var m = pkcs1pad2(text, this.n.bitLength() + 7 >> 3);
            if (null == m) return null;
            var c = this.doPublic(m);
            if (null == c) return null;
            var h = c.toString(16);
            return 0 == (1 & h.length) ? h : "0" + h
        };
        var rsaObj = new RSAKey,
            n = nn,
            e = ee;
        rsaObj.setPublic(n, e);
        var result = rsaObj.encrypt(val);
        if (256 != result.length)
            for (var l = Math.abs(256 - result.length), i = 0; i < l; i++) result = "0" + result;
        return result
    }, $.des = function (key, message, encrypt, mode, iv, padding)
    {
        encrypt && (message = unescape(encodeURIComponent(message)));
        var i, j, temp, right1, right2, left, right, looping, cbcleft, cbcleft2, cbcright, cbcright2, endloop, loopinc, spfunction1 = new Array(16843776, 0, 65536, 16843780, 16842756, 66564, 4, 65536, 1024, 16843776, 16843780, 1024, 16778244, 16842756, 16777216, 4, 1028, 16778240, 16778240, 66560, 66560, 16842752, 16842752, 16778244, 65540, 16777220, 16777220, 65540, 0, 1028, 66564, 16777216, 65536, 16843780, 4, 16842752, 16843776, 16777216, 16777216, 1024, 16842756, 65536, 66560, 16777220, 1024, 4, 16778244, 66564, 16843780, 65540, 16842752, 16778244, 16777220, 1028, 66564, 16843776, 1028, 16778240, 16778240, 0, 65540, 66560, 0, 16842756),
            spfunction2 = new Array(-2146402272, -2147450880, 32768, 1081376, 1048576, 32, -2146435040, -2147450848, -2147483616, -2146402272, -2146402304, -2147483648, -2147450880, 1048576, 32, -2146435040, 1081344, 1048608, -2147450848, 0, -2147483648, 32768, 1081376, -2146435072, 1048608, -2147483616, 0, 1081344, 32800, -2146402304, -2146435072, 32800, 0, 1081376, -2146435040, 1048576, -2147450848, -2146435072, -2146402304, 32768, -2146435072, -2147450880, 32, -2146402272, 1081376, 32, 32768, -2147483648, 32800, -2146402304, 1048576, -2147483616, 1048608, -2147450848, -2147483616, 1048608, 1081344, 0, -2147450880, 32800, -2147483648, -2146435040, -2146402272, 1081344),
            spfunction3 = new Array(520, 134349312, 0, 134348808, 134218240, 0, 131592, 134218240, 131080, 134217736, 134217736, 131072, 134349320, 131080, 134348800, 520, 134217728, 8, 134349312, 512, 131584, 134348800, 134348808, 131592, 134218248, 131584, 131072, 134218248, 8, 134349320, 512, 134217728, 134349312, 134217728, 131080, 520, 131072, 134349312, 134218240, 0, 512, 131080, 134349320, 134218240, 134217736, 512, 0, 134348808, 134218248, 131072, 134217728, 134349320, 8, 131592, 131584, 134217736, 134348800, 134218248, 520, 134348800, 131592, 8, 134348808, 131584),
            spfunction4 = new Array(8396801, 8321, 8321, 128, 8396928, 8388737, 8388609, 8193, 0, 8396800, 8396800, 8396929, 129, 0, 8388736, 8388609, 1, 8192, 8388608, 8396801, 128, 8388608, 8193, 8320, 8388737, 1, 8320, 8388736, 8192, 8396928, 8396929, 129, 8388736, 8388609, 8396800, 8396929, 129, 0, 0, 8396800, 8320, 8388736, 8388737, 1, 8396801, 8321, 8321, 128, 8396929, 129, 1, 8192, 8388609, 8193, 8396928, 8388737, 8193, 8320, 8388608, 8396801, 128, 8388608, 8192, 8396928),
            spfunction5 = new Array(256, 34078976, 34078720, 1107296512, 524288, 256, 1073741824, 34078720, 1074266368, 524288, 33554688, 1074266368, 1107296512, 1107820544, 524544, 1073741824, 33554432, 1074266112, 1074266112, 0, 1073742080, 1107820800, 1107820800, 33554688, 1107820544, 1073742080, 0, 1107296256, 34078976, 33554432, 1107296256, 524544, 524288, 1107296512, 256, 33554432, 1073741824, 34078720, 1107296512, 1074266368, 33554688, 1073741824, 1107820544, 34078976, 1074266368, 256, 33554432, 1107820544, 1107820800, 524544, 1107296256, 1107820800, 34078720, 0, 1074266112, 1107296256, 524544, 33554688, 1073742080, 524288, 0, 1074266112, 34078976, 1073742080),
            spfunction6 = new Array(536870928, 541065216, 16384, 541081616, 541065216, 16, 541081616, 4194304, 536887296, 4210704, 4194304, 536870928, 4194320, 536887296, 536870912, 16400, 0, 4194320, 536887312, 16384, 4210688, 536887312, 16, 541065232, 541065232, 0, 4210704, 541081600, 16400, 4210688, 541081600, 536870912, 536887296, 16, 541065232, 4210688, 541081616, 4194304, 16400, 536870928, 4194304, 536887296, 536870912, 16400, 536870928, 541081616, 4210688, 541065216, 4210704, 541081600, 0, 541065232, 16, 16384, 541065216, 4210704, 16384, 4194320, 536887312, 0, 541081600, 536870912, 4194320, 536887312),
            spfunction7 = new Array(2097152, 69206018, 67110914, 0, 2048, 67110914, 2099202, 69208064, 69208066, 2097152, 0, 67108866, 2, 67108864, 69206018, 2050, 67110912, 2099202, 2097154, 67110912, 67108866, 69206016, 69208064, 2097154, 69206016, 2048, 2050, 69208066, 2099200, 2, 67108864, 2099200, 67108864, 2099200, 2097152, 67110914, 67110914, 69206018, 69206018, 2, 2097154, 67108864, 67110912, 2097152, 69208064, 2050, 2099202, 69208064, 2050, 67108866, 69208066, 69206016, 2099200, 0, 2, 69208066, 0, 2099202, 69206016, 2048, 67108866, 67110912, 2048, 2097154),
            spfunction8 = new Array(268439616, 4096, 262144, 268701760, 268435456, 268439616, 64, 268435456, 262208, 268697600, 268701760, 266240, 268701696, 266304, 4096, 64, 268697600, 268435520, 268439552, 4160, 266240, 262208, 268697664, 268701696, 4160, 0, 0, 268697664, 268435520, 268439552, 266304, 262144, 266304, 262144, 268701696, 4096, 64, 268697664, 4096, 266304, 268439552, 64, 268435520, 268697600, 268697664, 268435456, 262144, 268439616, 0, 268701760, 262208, 268435520, 268697600, 268439552, 268439616, 0, 268701760, 266240, 266240, 4160, 4160, 262208, 268435456, 268701696),
            keys = $.des_createKeys(key),
            m = 0,
            len = message.length,
            chunk = 0,
            iterations = 32 == keys.length ? 3 : 9;
        looping = 3 == iterations ? encrypt ? new Array(0, 32, 2) : new Array(30, -2, -2) : encrypt ? new Array(0, 32, 2, 62, 30, -2, 64, 96, 2) : new Array(94, 62, -2, 32, 64, 2, 30, -2, -2), 2 == padding ? message += "        " : 1 == padding ? encrypt && (temp = 8 - len % 8, message += String.fromCharCode(temp, temp, temp, temp, temp, temp, temp, temp), 8 === temp && (len += 8)) : padding || (message += "\0\0\0\0\0\0\0\0");
        var result = "",
            tempresult = "";
        for (1 == mode && (cbcleft = iv.charCodeAt(m++) << 24 | iv.charCodeAt(m++) << 16 | iv.charCodeAt(m++) << 8 | iv.charCodeAt(m++), cbcright = iv.charCodeAt(m++) << 24 | iv.charCodeAt(m++) << 16 | iv.charCodeAt(m++) << 8 | iv.charCodeAt(m++), m = 0); m < len;)
        {
            for (left = message.charCodeAt(m++) << 24 | message.charCodeAt(m++) << 16 | message.charCodeAt(m++) << 8 | message.charCodeAt(m++), right = message.charCodeAt(m++) << 24 | message.charCodeAt(m++) << 16 | message.charCodeAt(m++) << 8 | message.charCodeAt(m++), 1 == mode && (encrypt ? (left ^= cbcleft, right ^= cbcright) : (cbcleft2 = cbcleft, cbcright2 = cbcright, cbcleft = left, cbcright = right)), left ^= (temp = 252645135 & (left >>> 4 ^ right)) << 4, left ^= (temp = 65535 & (left >>> 16 ^ (right ^= temp))) << 16, left ^= temp = 858993459 & ((right ^= temp) >>> 2 ^ left), left ^= temp = 16711935 & ((right ^= temp << 2) >>> 8 ^ left), left = (left ^= (temp = 1431655765 & (left >>> 1 ^ (right ^= temp << 8))) << 1) << 1 | left >>> 31, right = (right ^= temp) << 1 | right >>> 31, j = 0; j < iterations; j += 3)
            {
                for (endloop = looping[j + 1], loopinc = looping[j + 2], i = looping[j]; i != endloop; i += loopinc) right1 = right ^ keys[i], right2 = (right >>> 4 | right << 28) ^ keys[i + 1], temp = left, left = right, right = temp ^ (spfunction2[right1 >>> 24 & 63] | spfunction4[right1 >>> 16 & 63] | spfunction6[right1 >>> 8 & 63] | spfunction8[63 & right1] | spfunction1[right2 >>> 24 & 63] | spfunction3[right2 >>> 16 & 63] | spfunction5[right2 >>> 8 & 63] | spfunction7[63 & right2]);
                temp = left, left = right, right = temp
            }
            right = right >>> 1 | right << 31, right ^= temp = 1431655765 & ((left = left >>> 1 | left << 31) >>> 1 ^ right), right ^= (temp = 16711935 & (right >>> 8 ^ (left ^= temp << 1))) << 8, right ^= (temp = 858993459 & (right >>> 2 ^ (left ^= temp))) << 2, right ^= temp = 65535 & ((left ^= temp) >>> 16 ^ right), right ^= temp = 252645135 & ((left ^= temp << 16) >>> 4 ^ right), left ^= temp << 4, 1 == mode && (encrypt ? (cbcleft = left, cbcright = right) : (left ^= cbcleft2, right ^= cbcright2)), tempresult += String.fromCharCode(left >>> 24, left >>> 16 & 255, left >>> 8 & 255, 255 & left, right >>> 24, right >>> 16 & 255, right >>> 8 & 255, 255 & right), 512 == (chunk += 8) && (result += tempresult, tempresult = "", chunk = 0)
        }
        if (result += tempresult, result = result.replace(/\0*$/g, ""), !encrypt)
        {
            if (1 === padding)
            {
                var paddingChars = 0;
                (len = result.length) && (paddingChars = result.charCodeAt(len - 1)), paddingChars <= 8 && (result = result.substring(0, len - paddingChars))
            }
            result = decodeURIComponent(escape(result))
        }
        return result
    }, $.des_createKeys = function (key)
    {
        for (var lefttemp, righttemp, temp, pc2bytes0 = new Array(0, 4, 536870912, 536870916, 65536, 65540, 536936448, 536936452, 512, 516, 536871424, 536871428, 66048, 66052, 536936960, 536936964), pc2bytes1 = new Array(0, 1, 1048576, 1048577, 67108864, 67108865, 68157440, 68157441, 256, 257, 1048832, 1048833, 67109120, 67109121, 68157696, 68157697), pc2bytes2 = new Array(0, 8, 2048, 2056, 16777216, 16777224, 16779264, 16779272, 0, 8, 2048, 2056, 16777216, 16777224, 16779264, 16779272), pc2bytes3 = new Array(0, 2097152, 134217728, 136314880, 8192, 2105344, 134225920, 136323072, 131072, 2228224, 134348800, 136445952, 139264, 2236416, 134356992, 136454144), pc2bytes4 = new Array(0, 262144, 16, 262160, 0, 262144, 16, 262160, 4096, 266240, 4112, 266256, 4096, 266240, 4112, 266256), pc2bytes5 = new Array(0, 1024, 32, 1056, 0, 1024, 32, 1056, 33554432, 33555456, 33554464, 33555488, 33554432, 33555456, 33554464, 33555488), pc2bytes6 = new Array(0, 268435456, 524288, 268959744, 2, 268435458, 524290, 268959746, 0, 268435456, 524288, 268959744, 2, 268435458, 524290, 268959746), pc2bytes7 = new Array(0, 65536, 2048, 67584, 536870912, 536936448, 536872960, 536938496, 131072, 196608, 133120, 198656, 537001984, 537067520, 537004032, 537069568), pc2bytes8 = new Array(0, 262144, 0, 262144, 2, 262146, 2, 262146, 33554432, 33816576, 33554432, 33816576, 33554434, 33816578, 33554434, 33816578), pc2bytes9 = new Array(0, 268435456, 8, 268435464, 0, 268435456, 8, 268435464, 1024, 268436480, 1032, 268436488, 1024, 268436480, 1032, 268436488), pc2bytes10 = new Array(0, 32, 0, 32, 1048576, 1048608, 1048576, 1048608, 8192, 8224, 8192, 8224, 1056768, 1056800, 1056768, 1056800), pc2bytes11 = new Array(0, 16777216, 512, 16777728, 2097152, 18874368, 2097664, 18874880, 67108864, 83886080, 67109376, 83886592, 69206016, 85983232, 69206528, 85983744), pc2bytes12 = new Array(0, 4096, 134217728, 134221824, 524288, 528384, 134742016, 134746112, 16, 4112, 134217744, 134221840, 524304, 528400, 134742032, 134746128), pc2bytes13 = new Array(0, 4, 256, 260, 0, 4, 256, 260, 1, 5, 257, 261, 1, 5, 257, 261), iterations = key.length > 8 ? 3 : 1, keys = new Array(32 * iterations), shifts = new Array(0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0), m = 0, n = 0, j = 0; j < iterations; j++)
        {
            var left = key.charCodeAt(m++) << 24 | key.charCodeAt(m++) << 16 | key.charCodeAt(m++) << 8 | key.charCodeAt(m++),
                right = key.charCodeAt(m++) << 24 | key.charCodeAt(m++) << 16 | key.charCodeAt(m++) << 8 | key.charCodeAt(m++);
            left ^= (temp = 252645135 & (left >>> 4 ^ right)) << 4, left ^= temp = 65535 & ((right ^= temp) >>> -16 ^ left), left ^= (temp = 858993459 & (left >>> 2 ^ (right ^= temp << -16))) << 2, left ^= temp = 65535 & ((right ^= temp) >>> -16 ^ left), left ^= (temp = 1431655765 & (left >>> 1 ^ (right ^= temp << -16))) << 1, left ^= temp = 16711935 & ((right ^= temp) >>> 8 ^ left), temp = (left ^= (temp = 1431655765 & (left >>> 1 ^ (right ^= temp << 8))) << 1) << 8 | (right ^= temp) >>> 20 & 240, left = right << 24 | right << 8 & 16711680 | right >>> 8 & 65280 | right >>> 24 & 240, right = temp;
            for (var i = 0; i < shifts.length; i++) shifts[i] ? (left = left << 2 | left >>> 26, right = right << 2 | right >>> 26) : (left = left << 1 | left >>> 27, right = right << 1 | right >>> 27), right &= -15, lefttemp = pc2bytes0[(left &= -15) >>> 28] | pc2bytes1[left >>> 24 & 15] | pc2bytes2[left >>> 20 & 15] | pc2bytes3[left >>> 16 & 15] | pc2bytes4[left >>> 12 & 15] | pc2bytes5[left >>> 8 & 15] | pc2bytes6[left >>> 4 & 15], temp = 65535 & ((righttemp = pc2bytes7[right >>> 28] | pc2bytes8[right >>> 24 & 15] | pc2bytes9[right >>> 20 & 15] | pc2bytes10[right >>> 16 & 15] | pc2bytes11[right >>> 12 & 15] | pc2bytes12[right >>> 8 & 15] | pc2bytes13[right >>> 4 & 15]) >>> 16 ^ lefttemp), keys[n++] = lefttemp ^ temp, keys[n++] = righttemp ^ temp << 16
        }
        return keys
    }, $.genkey = function (key, start, end)
    {
        return {
            key: $.pad(key.slice(start, end)),
            vector: 1
        }
    }, $.pad = function (key)
    {
        for (var i = key.length; i < 24; i++) key += "0";
        return key
    }, $.DES3 = {
        encrypt: function (input)
        {
            var genKey = $.genkey("PKCS5Padding", 0, 24);
            return btoa($.des(genKey.key, input, 1, 1, "26951234", 1))
        },
        decrypt: function (input)
        {
            var genKey = $.genkey("PKCS5Padding", 0, 24);
            return $.des(genKey.key, atob(input), 0, 1, "26951234", 1)
        }
    }
}(jQuery);

module.exports = jQuery;
