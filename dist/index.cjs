Object.defineProperties(exports, {
	__esModule: { value: true },
	[Symbol.toStringTag]: { value: "Module" }
});
//#region \0rolldown/runtime.js
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) __defProp(target, name, {
		get: all[name],
		enumerable: true
	});
	if (!no_symbols) __defProp(target, Symbol.toStringTag, { value: "Module" });
	return target;
};
var __copyProps = (to, from, except, desc) => {
	if (from && typeof from === "object" || typeof from === "function") for (var keys = __getOwnPropNames(from), i = 0, n = keys.length, key; i < n; i++) {
		key = keys[i];
		if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, {
			get: ((k) => from[k]).bind(null, key),
			enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
		});
	}
	return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", {
	value: mod,
	enumerable: true
}) : target, mod));
//#endregion
let asn1_js = require("asn1.js");
asn1_js = __toESM(asn1_js, 1);
let buffer = require("buffer");
let node_crypto = require("node:crypto");
node_crypto = __toESM(node_crypto, 1);
let js_lzma = require("js-lzma");
js_lzma = __toESM(js_lzma, 1);
let fs = require("fs");
fs = __toESM(fs, 1);
let jksreader = require("jksreader");
jksreader = __toESM(jksreader, 1);
//#region lib/gf2m.js
var gf2m_exports = /* @__PURE__ */ __exportAll({
	blength: () => blength,
	inv_fast: () => finv_fast,
	inv_slow: () => finv_fermat,
	mod: () => fmod,
	mul: () => fmul,
	mul_2x2: () => mul_2x2,
	shiftRight: () => shiftRight
});
function blength(_bytes) {
	let r = 1;
	let t;
	let x;
	let nz;
	nz = _bytes.length - 1;
	while (_bytes[nz] === 0) nz--;
	x = _bytes[nz];
	if ((t = x >>> 16) !== 0) {
		x = t;
		r += 16;
	}
	if ((t = x >> 8) !== 0) {
		x = t;
		r += 8;
	}
	if ((t = x >> 4) !== 0) {
		x = t;
		r += 4;
	}
	if ((t = x >> 2) !== 0) {
		x = t;
		r += 2;
	}
	if ((t = x >> 1) !== 0) {
		x = t;
		r += 1;
	}
	return r + nz * 32;
}
function shiftRight(_bytes, right, inplace) {
	const wright = Math.floor(right / 32);
	right %= 32;
	let idx;
	const blen = _bytes.length;
	const left = 32 - right;
	let mask_f = (1 << 1 + right) - 1;
	let _rbytes;
	let tmp;
	if (right === 31) mask_f = 4294967295;
	if (inplace === true) _rbytes = _bytes;
	else _rbytes = new Uint32Array(blen);
	_rbytes[0] = _bytes[0] >>> right;
	for (idx = 1; idx < blen; idx++) {
		tmp = _bytes[idx] & mask_f;
		_rbytes[idx] = _bytes[idx] >>> right;
		_rbytes[idx - 1] |= tmp << left;
	}
	if (wright === 0) return _rbytes;
	for (idx = 0; idx < blen; idx++) _rbytes[idx] = _rbytes[idx + wright] || 0;
	return _rbytes;
}
function mul_1x1(ret, offset, a, b) {
	const top2b = a >>> 30;
	const ol = offset;
	const oh = offset + 1;
	let s;
	let l;
	let h;
	const a1 = a & 1073741823;
	const a2 = a1 << 1;
	const a4 = a2 << 1;
	const tab = [
		0,
		a1,
		a2,
		a1 ^ a2,
		a4,
		a1 ^ a4,
		a2 ^ a4,
		a1 ^ a2 ^ a4
	];
	s = tab[b & 7];
	l = s;
	s = tab[b >>> 3 & 7];
	l ^= s << 3;
	h = s >>> 29;
	s = tab[b >>> 6 & 7];
	l ^= s << 6;
	h ^= s >>> 26;
	s = tab[b >>> 9 & 7];
	l ^= s << 9;
	h ^= s >>> 23;
	s = tab[b >>> 12 & 7];
	l ^= s << 12;
	h ^= s >>> 20;
	s = tab[b >>> 15 & 7];
	l ^= s << 15;
	h ^= s >>> 17;
	s = tab[b >>> 18 & 7];
	l ^= s << 18;
	h ^= s >>> 14;
	s = tab[b >>> 21 & 7];
	l ^= s << 21;
	h ^= s >>> 11;
	s = tab[b >>> 24 & 7];
	l ^= s << 24;
	h ^= s >>> 8;
	s = tab[b >>> 27 & 7];
	l ^= s << 27;
	h ^= s >>> 5;
	s = tab[b >>> 30];
	l ^= s << 30;
	h ^= s >>> 2;
	if (top2b & 1) {
		l ^= b << 30;
		h ^= b >>> 2;
	}
	if (top2b & 2) {
		l ^= b << 31;
		h ^= b >>> 1;
	}
	ret[oh] = h;
	ret[ol] = l;
}
function mul_2x2(a1, a0, b1, b0, ret) {
	mul_1x1(ret, 2, a1, b1);
	mul_1x1(ret, 0, a0, b0);
	mul_1x1(ret, 4, a0 ^ a1, b0 ^ b1);
	ret[2] ^= ret[5] ^ ret[1] ^ ret[3];
	ret[1] = ret[3] ^ ret[2] ^ ret[0] ^ ret[4] ^ ret[5];
	ret[4] = 0;
	ret[5] = 0;
	return ret;
}
function fmul(a, b, s) {
	let y1;
	let y0;
	let x1;
	let x0;
	const a_len = a.length;
	const b_len = b.length;
	for (let i = 0; i < s.length; i++) s[i] = 0;
	const x22 = /* @__PURE__ */ new Uint32Array(6);
	for (let j = 0; j < b_len; j += 2) {
		y0 = b[j];
		y1 = j + 1 === b_len ? 0 : b[j + 1];
		for (let i = 0; i < a_len; i += 2) {
			x0 = a[i];
			x1 = i + 1 === a_len ? 0 : a[i + 1];
			mul_2x2(x1, x0, y1, y0, x22);
			s[j + i + 0] ^= x22[0];
			s[j + i + 1] ^= x22[1];
			s[j + i + 2] ^= x22[2];
			s[j + i + 3] ^= x22[3];
		}
	}
}
const BITS = 32;
function fmod(a, p, ret) {
	let ret_len;
	let zz;
	let k;
	let n;
	let d0;
	let d1;
	let tmp_ulong;
	let j;
	if (ret) {
		ret_len = ret.length;
		for (k = 0; k < ret_len; k++) ret[k] = a[k];
	} else {
		ret_len = a.length;
		ret = new Uint32Array(ret_len);
		for (k = 0; k < ret_len; k++) ret[k] = a[k];
	}
	const dN = Math.floor(p[0] / BITS);
	for (j = ret_len - 1; j > dN;) {
		zz = ret[j];
		if (ret[j] === 0) {
			j--;
			continue;
		}
		ret[j] = 0;
		for (k = 1; p[k]; k++) {
			n = p[0] - p[k];
			d0 = n % BITS;
			d1 = BITS - d0;
			n = Math.floor(n / BITS);
			ret[j - n] ^= zz >>> d0;
			if (d0) ret[j - n - 1] ^= zz << d1;
		}
		n = dN;
		d0 = p[0] % BITS;
		d1 = BITS - d0;
		ret[j - n] ^= zz >>> d0;
		if (d0) ret[j - n - 1] ^= zz << d1;
	}
	while (j === dN) {
		d0 = p[0] % BITS;
		zz = ret[dN] >>> d0;
		if (zz === 0) break;
		d1 = BITS - d0;
		if (d0) ret[dN] = ret[dN] << d1 >>> d1;
		else ret[dN] = 0;
		ret[0] ^= zz;
		for (k = 1; p[k]; k++) {
			n = Math.floor(p[k] / BITS);
			d0 = p[k] % BITS;
			d1 = BITS - d0;
			ret[n] ^= zz << d0;
			tmp_ulong = zz >>> d1;
			if (d0 && tmp_ulong) ret[n + 1] ^= tmp_ulong;
		}
	}
	return ret;
}
function finv_fast(a, p, ret) {
	let b = new Uint32Array(a.length);
	let c = new Uint32Array(a.length);
	let v = new Uint32Array(a.length);
	b[0] = 1;
	let u = a;
	for (let idx = 0; idx < p.length; idx++) v[idx] = p[idx];
	let ubits = blength(u);
	let vbits = blength(v);
	let iter = 1e3;
	while (1) {
		iter--;
		if (iter <= 0) throw new Error("Internal error, loop");
		if (ubits < 0) throw new Error("Internal error");
		while (ubits && !(u[0] & 1)) {
			let u0 = u[0];
			let b0 = b[0];
			let u1;
			let b1;
			const mask = b0 & 1 ? 4294967295 : 0;
			b0 ^= p[0] & mask;
			let idx;
			for (idx = 0; idx < p.length - 1; idx++) {
				u1 = u[idx + 1];
				u[idx] = u0 >>> 1 | u1 << 31;
				u0 = u1;
				b1 = b[idx + 1] ^ p[idx + 1] & mask;
				b[idx] = b0 >>> 1 | b1 << 31;
				b0 = b1;
			}
			u[idx] = u0 >> 1;
			b[idx] = b0 >> 1;
			ubits--;
		}
		if (ubits <= 32 && u[0] === 1) break;
		if (ubits < vbits) {
			let tmp = ubits;
			ubits = vbits;
			vbits = tmp;
			tmp = u;
			u = v;
			v = tmp;
			tmp = b;
			b = c;
			c = tmp;
		}
		for (let idx = 0; idx < p.length; idx++) {
			u[idx] ^= v[idx];
			b[idx] ^= c[idx];
		}
		if (ubits === vbits) ubits = blength(u);
	}
	for (let idx = 0; idx < b.length; idx++) ret[idx] = b[idx];
}
function finv_fermat(m, a, p, ret) {
	const len = a.length * 2;
	let x = new Uint32Array(len);
	for (let i = 0; i < len; i++) x[i] = a[i];
	let temp = new Uint32Array(len);
	for (let i = 0; i < m - 2; i++) {
		fmul(x, x, temp);
		fmod(temp, p, x);
		fmul(x, a, temp);
		fmod(temp, p, x);
	}
	fmul(x, x, temp);
	fmod(temp, p, x);
	for (let i = 0; i < len; i++) ret[i] = x[i];
}
//#endregion
//#region lib/field.js
let impl = gf2m_exports;
var Field = class Field {
	constructor(in_value, fmt, curve) {
		if (curve === void 0 || curve.mod_words === void 0) throw new Error("pass curve to field constructor");
		if (in_value !== null && in_value._is_field) throw new Error("wtf");
		if (in_value === null) {
			this.bytes = new Uint32Array(curve.mod_words);
			this.length = curve.mod_words;
		} else this.setValue(in_value, fmt, curve.mod_words);
		this._is_field = true;
		this.curve = curve;
		this.mod_bits = curve.mod_bits;
		this.mod_words = curve.mod_words;
	}
	toString(raw) {
		let txt = "", chr, skip = true, _bytes = this.bytes;
		for (let i = _bytes.length - 1; i >= 0; i--) {
			chr = _bytes[i].toString(16);
			if (skip && _bytes[i] == 0) continue;
			while (chr.length < 8 && skip === false) chr = "0" + chr;
			txt += chr;
			skip = false;
		}
		if (raw === true) return txt;
		return "<Field " + txt + ">";
	}
	mod_mul(that) {
		let s = this.curve.mod_tmp;
		impl.mul(this.bytes, that.bytes, s);
		s = impl.mod(s, this.mod_bits).subarray(0, this.mod_words);
		return new Field(s, void 0, this.curve);
	}
	mod_sqr() {
		return this.mod_mul(this);
	}
	mod() {
		let rbuf = impl.mod(this.bytes, this.mod_bits);
		return new Field(rbuf, void 0, this.curve);
	}
	addM(that, _from) {
		let that_b = that.bytes, that_len = that_b.length, this_b = _from || this.bytes, to_b = this.bytes, iter_len = Math.max((to_b || _from).length, that_len), i;
		if (to_b.length < that_len) to_b = new Uint32Array(this.mod_words);
		for (i = 0; i < iter_len; i++) to_b[i] = this_b[i] ^ (that_b[i] || 0);
		this.bytes = to_b;
		this.length = to_b.length;
	}
	add(that) {
		let ret = new Field(null, void 0, this.curve);
		ret.addM(that, this.bytes);
		return ret;
	}
	is_zero() {
		let blen = this.length, idx;
		for (idx = 0; idx < blen; idx++) if (this.bytes[idx] !== 0) return false;
		return true;
	}
	equals(other) {
		let blen = this.length, olen = other.length, idx, bb = this.bytes, diff = 0, ob = other.bytes;
		while (ob[olen - 1] === 0) olen--;
		while (bb[blen - 1] === 0) blen--;
		if (olen != blen) return false;
		for (idx = 0; idx < blen; idx++) diff |= this.bytes[idx] ^ ob[idx];
		return diff === 0;
	}
	less(other) {
		let blen = this.length, olen = other.length, bb = this.bytes, ob = other.bytes;
		while (olen > 0 && ob[olen - 1] === 0) olen--;
		while (blen > 0 && bb[blen - 1] === 0) blen--;
		if (blen < olen) return true;
		if (olen < blen) return false;
		for (let i = blen - 1; i >= 0; i--) {
			if (bb[i] < ob[i]) return true;
			if (bb[i] > ob[i]) return false;
		}
		return false;
	}
	bitLength() {
		return blength(this.bytes);
	}
	testBit(n) {
		let test_word = Math.floor(n / 32), test_bit = n % 32, word = this.bytes[test_word], mask = 1 << test_bit;
		if (word === void 0) return true;
		return (word & mask) !== 0;
	}
	clone() {
		return new Field(new Uint32Array(this.bytes), void 0, this.curve);
	}
	clearBit(n) {
		let test_word = Math.floor(n / 32), test_bit = n % 32, word = this.bytes[test_word], mask = 1 << test_bit;
		if (word === void 0) return this;
		word ^= word & mask;
		let ret = this.clone();
		ret.bytes[test_word] = word;
		return ret;
	}
	setBit(n) {
		let test_word = Math.floor(n / 32), test_bit = n % 32, word = this.bytes[test_word], mask = 1 << test_bit;
		if (word === void 0) return this;
		let ret = this.clone();
		ret.bytes[test_word] |= mask;
		return ret;
	}
	shiftRight(bits) {
		if (bits === 0) return this.clone();
		return new Field(shiftRight(this.bytes, bits, false), void 0, this.curve);
	}
	shiftRightM(bits) {
		if (bits === 0) return;
		shiftRight(this.bytes, bits, true);
	}
	buf8() {
		let ret = new Uint8Array(this.bytes.length * 4);
		let l = ret.length;
		let idx;
		for (idx = 0; idx < this.bytes.length; idx++) {
			ret[l - idx * 4 - 1] = this.bytes[idx] & 255;
			ret[l - idx * 4 - 2] = this.bytes[idx] >>> 8 & 255;
			ret[l - idx * 4 - 3] = this.bytes[idx] >>> 16 & 255;
			ret[l - idx * 4 - 4] = this.bytes[idx] >>> 24 & 255;
		}
		return ret;
	}
	le() {
		let bytes = Math.ceil(this.curve.m / 8);
		let data = this.buf8();
		data = Array.prototype.slice.call(data, 0);
		return buffer.Buffer.from(data.reverse()).slice(0, bytes);
	}
	truncate_buf8() {
		let ret = this.buf8(), start = ret.length - this.curve.order.bitLength() / 8;
		if (start < 0) return ret;
		return ret.subarray(start);
	}
	is_negative() {
		return false;
	}
	trace() {
		let bitm_l = this.curve.m;
		let idx;
		let rv = this;
		for (idx = 1; idx <= bitm_l - 1; idx++) {
			rv = rv.mod_mul(rv);
			rv.addM(this);
		}
		return rv.bytes[0] & 1;
	}
	setValue(in_value, fmt, mod_words) {
		if (in_value !== null && in_value._is_field) throw new Error("wtf");
		if (fmt === void 0 || fmt === "buf32") {
			this.bytes = in_value;
			this.length = in_value.length;
			return;
		}
		if (fmt === "hex") {
			this.bytes = from_hex(in_value, mod_words);
			this.length = this.bytes.length;
			return;
		}
		if (fmt === "bn") {
			in_value = in_value.toArray();
			fmt = "buf8";
		}
		if (fmt === "buf8") {
			this.bytes = from_u8(in_value, mod_words);
			this.length = this.bytes.length;
		}
	}
	invert(inplace, _reuse_buf) {
		let a = impl.mod(this.bytes, this.mod_bits);
		let p = this.curve.calc_modulus(this.mod_bits);
		if (this.curve.m == 191) impl.inv_slow(this.curve.m, a, this.mod_bits, a);
		else impl.inv_fast(a, p, a);
		return new Field(a, void 0, this.curve);
	}
	static detect_format(in_value) {
		if (typeof in_value === "string") return "hex";
		else if (in_value instanceof Uint8Array) return "buf8";
		else if (in_value instanceof Uint32Array) return "buf32";
		else throw new Error("Unknown format");
	}
	static parse_sign(in_value, fmt, curve) {
		return new Field(in_value, fmt, curve);
	}
};
const HEX = "0123456789ABCDEF";
function from_hex(in_value, max_size) {
	let idx;
	let chr;
	let code;
	let vidx = 0;
	let bpos = 0;
	let size = Math.ceil(in_value.length / 8);
	size = Math.max(size, max_size || size);
	let value = new Uint32Array(size);
	for (idx = in_value.length - 1; idx >= 0; idx--) {
		chr = in_value.charAt(idx).toUpperCase();
		code = HEX.indexOf(chr);
		bpos = bpos % 8;
		if (code < 0) throw new Error("Wrong input at " + idx);
		value[vidx] |= code << bpos * 4;
		if (bpos == 7) vidx++;
		bpos++;
	}
	return value;
}
function from_u8(in_value, max_size) {
	let vidx = 0;
	let bpos = 0;
	let size = Math.ceil(in_value.length / 4);
	size = Math.max(size, max_size || size);
	let value = new Uint32Array(size);
	let idx;
	let code;
	if (in_value.toString() === "[object Uint32Array]") throw new Error("fuck off");
	for (idx = in_value.length - 1; idx >= 0; idx--) {
		code = in_value[idx];
		bpos = bpos % 4;
		if (code < 0) code = 256 + code;
		value[vidx] |= code << bpos * 8;
		if (bpos === 3) vidx++;
		bpos++;
	}
	return value;
}
//#endregion
//#region lib/wnaf/wnaf.js
var DEFAULT_CUTOFFS = [
	13,
	41,
	121,
	337,
	897,
	2305
];
function windowNaf(width, bigint) {
	var wnaf, ret_len;
	bigint = bigint.clone();
	if (width === 2) return compactNaf(bigint);
	ret_len = Math.floor(bigint.bitLength() / width + 1);
	wnaf = new Int32Array(ret_len);
	var pow2 = 1 << width;
	var masbigint = pow2 - 1;
	var sign = pow2 >>> 1;
	var carry = false;
	var length = 0, pos = 0;
	var digit, zeroes;
	while (pos <= bigint.bitLength()) {
		if (bigint.testBit(pos) === carry) {
			++pos;
			continue;
		}
		bigint.shiftRightM(pos);
		digit = bigint.bytes[0] & masbigint;
		if (carry) ++digit;
		carry = (digit & sign) !== 0;
		if (carry) digit -= pow2;
		zeroes = length > 0 ? pos - 1 : pos;
		wnaf[length++] = digit << 16 | zeroes;
		pos = width;
	}
	if (wnaf.length > length) wnaf = wnaf.subarray(0, length);
	return wnaf;
}
function compactNaf(k) {
	if (k.bitLength() >>> 16 != 0) throw new Error("'k' must have bitlength < 2^16");
	if (k.signum() == 0) return /* @__PURE__ */ new Int32Array(0);
	var _3k = k.shiftLeft(1).add(k);
	var bits = _3k.bitLength();
	var naf = new Int32Array(bits >> 1);
	var diff = _3k.xor(k);
	var highBit = bits - 1, length = 0, zeroes = 0;
	var i, digit;
	for (i = 1; i < highBit; ++i) {
		if (!diff.testBit(i)) {
			++zeroes;
			continue;
		}
		digit = k.testBit(i) ? -1 : 1;
		naf[length++] = digit << 16 | zeroes;
		zeroes = 1;
		++i;
	}
	naf[length++] = 65536 | zeroes;
	if (naf.length > length) naf = naf.subarray(0, length);
	return naf;
}
function _getWindowSize(bits, cutoffs) {
	var i, cuts = cutoffs.length;
	for (i = 0; i < cuts; ++i) if (bits < cutoffs[i]) break;
	return i + 2;
}
function getWindowSize$1(bits) {
	return _getWindowSize(bits, DEFAULT_CUTOFFS);
}
//#endregion
//#region lib/wnaf/mul.js
let bitLengths;
bitLengths = new Uint8Array([
	0,
	1,
	2,
	2,
	3,
	3,
	3,
	3,
	4,
	4,
	4,
	4,
	4,
	4,
	4,
	4,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	5,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	6,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	7,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8
]);
var precomp$1 = function(point, width) {
	var i, len_off = width - 2, len, rpos, rneg, twice;
	if (len_off < 0) len_off = 0;
	len = 1 << len_off;
	rpos = point._precomp.pos;
	rneg = point._precomp.neg;
	i = rpos.length;
	if (!rneg[0]) rneg[0] = point.negate();
	if (len === 1) return {
		pos: rpos,
		neg: rneg
	};
	twice = point._twice || (point._twice = point.twice());
	for (; i < len; i++) {
		rpos[i] = twice.add(rpos[i - 1]);
		rneg[i] = rpos[i].negate();
	}
	return {
		pos: rpos,
		neg: rneg
	};
};
var mulPos$1 = function(point, big_k) {
	var width = getWindowSize$1(big_k.bitLength());
	width = Math.max(2, Math.min(16, width));
	var precomps = precomp$1(point, width);
	var ppos = precomps.pos;
	var pneg = precomps.neg;
	var wnaf = windowNaf(width, big_k);
	var R = point.Inf;
	var i = wnaf.length;
	if (i > 1) {
		var wi = wnaf[--i];
		var digit = wi >> 16, zeroes = wi & 65535;
		var n = Math.abs(digit);
		var table = digit < 0 ? pneg : ppos;
		if (n << 2 < 1 << width) {
			var highest = bitLengths[n];
			var scale = width - highest;
			var lowBits = n ^ 1 << highest - 1;
			var i1 = (1 << width - 1) - 1;
			var i2 = (lowBits << scale) + 1;
			R = table[i1 >>> 1].add(table[i2 >>> 1]);
			zeroes -= scale;
		} else R = table[n >>> 1];
		R = R.timesPow2(zeroes);
	}
	var wi, digit, n, table, r;
	while (i > 0) {
		wi = wnaf[--i];
		digit = wi >> 16, zeroes = wi & 65535;
		n = Math.abs(digit);
		table = digit < 0 ? pneg : ppos;
		r = table[n >>> 1];
		R = R.twicePlus(r);
		R = R.timesPow2(zeroes);
	}
	return R;
};
//#endregion
//#region lib/wnaf/index.js
const precomp = precomp$1;
const mulPos = mulPos$1;
const getWindowSize = getWindowSize$1;
//#endregion
//#region lib/util.js
function add_zero(u8, reorder) {
	let ret = [], i;
	if (u8.toBuffer !== void 0) u8 = u8.toBuffer();
	if (reorder !== true) ret.push(0);
	for (i = 0; i < u8.length; i++) ret.push(u8[i]);
	if (reorder === true) {
		ret.push(0);
		ret = ret.reverse();
	}
	return ret;
}
function invert(u8) {
	let cr, ret = [];
	for (i = u8.length - 1; i >= 0; i--) {
		cr = u8[i];
		cr = cr >> 7 | cr >> 5 & 2 | cr >> 3 & 4 | cr >> 1 & 8 | cr << 1 & 16 | cr << 3 & 32 | cr << 5 & 64 | cr << 7 & 128;
		ret.push(cr);
	}
	return ret;
}
const HEX_REGEXP = /^[A-Fa-f0-9]+$/;
function is_hex(inp) {
	let res;
	if (typeof inp !== "string") return false;
	res = inp.match(HEX_REGEXP);
	if (res === null) return false;
	return res.length > 0;
}
function BIG_BE(inp) {
	return from_u8(inp);
}
function BIG_LE(inp) {
	return from_u8(Array.prototype.slice.call(inp, 0).reverse());
}
function BIG_INVERT(inp) {
	return add_zero(invert(inp));
}
function maybeHex(inp, pad) {
	let tmp, ret;
	if (typeof inp === "number") ret = [0, inp];
	if (typeof inp === "string") {
		tmp = inp.replace(/ /g, "");
		if (is_hex(tmp)) return from_hex(tmp, pad);
	}
	if (!ret) ret = inp;
	if (pad) {
		if (!ret.push) ret = Array.prototype.slice.call(inp, 0);
		while (pad--) ret.push(0);
	}
	return new Uint32Array(ret);
}
//#endregion
//#region lib/rand.js
function rand_default(xb) {
	const ret = node_crypto.default.rng(xb.length);
	for (let i = 0; i < xb.length; i++) xb[i] = ret[i];
	return ret;
}
//#endregion
//#region lib/util/base64.js
var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
var B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
var B64_TEST = /[^A-Za-z0-9\+\/\=]/g;
var B64_REPLACE = /[^A-Za-z0-9\+\/]/g;
var b64_encode = function(numbrs, line, safe, pad) {
	var table, ret = [], b1, b2, b3, e1, e2, e3, e4, i = 0;
	if (typeof line === "object") {
		safe = line.safe;
		pad = line.pad;
		line = line.line;
	}
	if (safe === true) table = B64_URL;
	else table = B64;
	while (i < numbrs.length) {
		if (i > 0 && line !== void 0 && i % line === 0) ret.push("\n");
		b1 = numbrs[i++];
		b2 = numbrs[i++];
		b3 = numbrs[i++];
		e1 = b1 >> 2;
		e2 = (b1 & 3) << 4 | b2 >> 4;
		e3 = (b2 & 15) << 2 | b3 >> 6;
		e4 = b3 & 63;
		ret.push(table.charAt(e1));
		ret.push(table.charAt(e2));
		if (b2 !== void 0) ret.push(table.charAt(e3));
		if (b3 !== void 0) ret.push(table.charAt(e4));
	}
	i = numbrs.length % 3;
	if (pad && i === 2) ret.push("=");
	if (pad && i === 1) ret.push("==");
	return ret.join("");
};
var b64_decode = function(input) {
	var output, output_len, chr1, chr2, chr3, enc1, enc2, enc3, enc4, i = 0, o = 0;
	if (B64_TEST.exec(input)) throw new Error("invalid b64 input");
	input = input.replace(B64_REPLACE, "");
	output_len = Math.floor(input.length * 3 / 4);
	output = buffer.Buffer.alloc(output_len);
	do {
		enc1 = B64.indexOf(input.charAt(i++));
		enc2 = B64.indexOf(input.charAt(i++));
		enc3 = B64.indexOf(input.charAt(i++));
		enc4 = B64.indexOf(input.charAt(i++));
		chr1 = enc1 << 2 | enc2 >> 4;
		chr2 = (enc2 & 15) << 4 | enc3 >> 2;
		chr3 = (enc3 & 3) << 6 | enc4;
		output[o++] = chr1;
		output[o++] = chr2;
		output[o++] = chr3;
	} while (i < input.length);
	return output;
};
//#endregion
//#region lib/util/pem.js
var is_pem = function(indata) {
	if (indata.constructor === Uint8Array || buffer.Buffer.isBuffer(indata)) {
		if (indata[0] === 45 && indata[1] === 45 && indata[2] === 45 && indata[3] === 45 && indata[4] === 45) return true;
	}
	if (typeof indata === "string") return indata.indexOf("-----") === 0;
};
var from_pem = function(indata) {
	var start, end, ln;
	if (typeof indata !== "string") indata = String.fromCharCode.apply(null, indata);
	indata = indata.split("\n");
	for (start = 0; start < indata.length; start++) {
		ln = indata[start];
		if (ln.indexOf("-----") === 0) {
			start++;
			break;
		}
	}
	for (end = 1; end <= indata.length; end++) {
		ln = indata[indata.length - end];
		if (ln.indexOf("-----") === 0) break;
	}
	indata = indata.slice(start, -end).join("");
	return b64_decode(indata);
};
var maybe_pem = function(indata) {
	if (is_pem(indata)) return from_pem(indata);
	return indata;
};
//#endregion
//#region lib/spec/rfc3280.js
var rfc3280_exports = /* @__PURE__ */ __exportAll({
	ALGORITHMS_IDS: () => ALGORITHMS_IDS,
	AlgorithmIdentifier: () => AlgorithmIdentifier,
	AttributeType: () => AttributeType,
	AttributeTypeAndValue: () => AttributeTypeAndValue,
	AttributeValue: () => AttributeValue,
	BasicConstraints: () => BasicConstraints,
	CRLReason: () => CRLReason,
	Certificate: () => Certificate$1,
	CertificateSerialNumber: () => CertificateSerialNumber$1,
	ExtKeyUsageSyntax: () => ExtKeyUsageSyntax,
	Extension: () => Extension,
	Extensions: () => Extensions,
	Name: () => Name,
	RDNSequence: () => RDNSequence,
	RelativeDistinguishedName: () => RelativeDistinguishedName,
	SubjectPublicKeyInfo: () => SubjectPublicKeyInfo,
	TBSCertificate: () => TBSCertificate,
	Time: () => Time,
	UniqueIdentifier: () => UniqueIdentifier,
	Validity: () => Validity,
	Version: () => Version$1,
	injectPubAlgo: () => injectPubAlgo
});
var CRLReason = asn1_js.default.define("CRLReason", function() {
	this.enum({
		0: "unspecified",
		1: "keyCompromise",
		2: "CACompromise",
		3: "affiliationChanged",
		4: "superseded",
		5: "cessationOfOperation",
		6: "certificateHold",
		8: "removeFromCRL",
		9: "privilegeWithdrawn",
		10: "AACompromise"
	});
});
var ALGORITHMS_IDS = {
	"1 2 804 2 1 1 1 1 2 1": "Gost34311",
	"1 2 804 2 1 1 1 1 1 1 3": "Gost28147-cfb",
	"1 2 804 2 1 1 1 1 3 4": "dhSinglePass-cofactorDH-gost34311kdf",
	"1 2 804 2 1 1 1 1 1 1 5": "Gost28147-cfb-wrap",
	"1 2 804 2 1 1 1 1 1 2": "Gost34311-hmac",
	"1 2 804 2 1 1 1 1 3 1 1": "Dstu4145le",
	"1 2 840 10045 2 1": "ECDSA",
	"1 2 840 10045 4 3 2": "ECDSA-SHA256"
};
var AlgorithmIdentifier = asn1_js.default.define("AlgorithmIdentifier", function() {
	this.seq().obj(this.key("algorithm").objid(ALGORITHMS_IDS), this.key("parameters").optional().any());
});
var Certificate$1 = asn1_js.default.define("Certificate", function() {
	this.seq().obj(this.key("tbsCertificate").use(TBSCertificate), this.key("signatureAlgorithm").use(AlgorithmIdentifier), this.key("signature").bitstr());
});
var TBSCertificate = asn1_js.default.define("TBSCertificate", function() {
	this.seq().obj(this.key("version").def("v1").explicit(0).use(Version$1), this.key("serialNumber").use(CertificateSerialNumber$1), this.key("signature").use(AlgorithmIdentifier), this.key("issuer").use(Name), this.key("validity").use(Validity), this.key("subject").use(Name), this.key("subjectPublicKeyInfo").use(SubjectPublicKeyInfo), this.key("issuerUniqueID").optional().implicit(1).use(UniqueIdentifier), this.key("subjectUniqueID").optional().implicit(2).use(UniqueIdentifier), this.key("extensions").optional().explicit(3).use(Extensions));
});
var Version$1 = asn1_js.default.define("Version", function() {
	this.int({
		0: "v1",
		1: "v2",
		2: "v3"
	});
});
var CertificateSerialNumber$1 = asn1_js.default.define("CertificateSerialNumber", function() {
	this.int();
});
var Validity = asn1_js.default.define("Validity", function() {
	this.seq().obj(this.key("notBefore").use(Time), this.key("notAfter").use(Time));
});
var Time = asn1_js.default.define("Time", function() {
	this.choice({
		utcTime: this.utctime(),
		genTime: this.gentime()
	});
});
var UniqueIdentifier = asn1_js.default.define("UniqueIdentifier", function() {
	this.bitstr();
});
var PUBKEY_PARAMS = { any: asn1_js.default.define("AlgorithmParams", function() {
	this.any();
}) };
var PubkeyAlgorithmIdentifier = asn1_js.default.define("PubkeyAlgorithmIdentifier", function() {
	this.seq().obj(this.key("algorithm").objid(ALGORITHMS_IDS), this.key("parameters").use(function(obj) {
		return PUBKEY_PARAMS[obj.algorithm] || PUBKEY_PARAMS.any;
	}));
});
var SubjectPublicKeyInfo = asn1_js.default.define("SubjectPublicKeyInfo", function() {
	this.seq().obj(this.key("algorithm").use(PubkeyAlgorithmIdentifier), this.key("subjectPublicKey").bitstr());
});
var Extensions = asn1_js.default.define("Extensions", function() {
	this.seqof(Extension);
});
var extnIdMap = {
	"1 3 6 1 5 5 7 1 1": "authorityInfoAccess",
	"1 3 6 1 5 5 7 1 2": "biometricInfo",
	"1 3 6 1 5 5 7 1 3": "qcStatements",
	"1 3 6 1 5 5 7 1 4": "ac-auditEntity",
	"1 3 6 1 5 5 7 1 5": "ac-targeting",
	"1 3 6 1 5 5 7 1 6": "aaControls",
	"1 3 6 1 5 5 7 1 7": "sbgp-ipAddrBlock",
	"1 3 6 1 5 5 7 1 8": "sbgp-autonomousSysNum",
	"1 3 6 1 5 5 7 1 9": "sbgp-routerIdentifier",
	"1 3 6 1 5 5 7 1 10": "ac-proxying",
	"1 3 6 1 5 5 7 1 11": "subjectInfoAccess",
	"1 3 6 1 5 5 7 1 14": "proxyCertInfo",
	"2 5 29 9": "subjectDirectoryAttributes",
	"2 5 29 14": "subjectKeyIdentifier",
	"2 5 29 15": "keyUsage",
	"2 5 29 16": "privateKeyUsagePeriod",
	"2 5 29 17": "subjectAltName",
	"2 5 29 18": "issuerAltName",
	"2 5 29 19": "basicConstraints",
	"2 5 29 20": "crlNumber",
	"2 5 29 21": "CRLReason",
	"2 5 29 24": "invalidityDate",
	"2 5 29 27": "deltaCRL",
	"2 5 29 28": "issuingDistributionPoint",
	"2 5 29 29": "certificateIssuer",
	"2 5 29 30": "nameConstraints",
	"2 5 29 31": "crlDistributionPoints",
	"2 5 29 32": "certificatePolicies",
	"2 5 29 32 0": "anyPolicy",
	"2 5 29 33": "policyMappings",
	"2 5 29 35": "authorityKeyIdentifier",
	"2 5 29 36": "policyConstraints",
	"2 5 29 37": "extendedKeyUsage",
	"2 5 29 46": "freshestCRL",
	"2 5 29 54": "inhibitAnyPolicy",
	"2 5 29 55": "targetInformation",
	"2 5 29 56": "noRevAvail",
	"1 3 6 1 5 5 7 48 1 2": "OCSPNonce"
};
var Extension = asn1_js.default.define("Extension", function() {
	this.seq().obj(this.key("extnID").objid(extnIdMap), this.key("critical").bool().def(false), this.key("extnValue").octstr());
});
/**

Name ::= CHOICE { -- only one possibility for now --
rdnSequence  RDNSequence }

*/
var Name = asn1_js.default.define("Name", function() {
	this.choice({ rdn: this.use(RDNSequence) });
});
var RDNSequence = asn1_js.default.define("RDNSequence", function() {
	this.seqof(RelativeDistinguishedName);
});
var RelativeDistinguishedName = asn1_js.default.define("RelativeDistinguishedName", function() {
	this.setof(AttributeTypeAndValue);
});
var AttributeTypeAndValue = asn1_js.default.define("AttributeTypeAndValue", function() {
	this.seq().obj(this.key("type").use(AttributeType), this.key("value").use(AttributeValue));
});
var AttributeObjId = {
	"1 2 840 113549 1 9 3": "contentType",
	"1 2 840 113549 1 9 4": "messageDigest",
	"1 2 840 113549 1 9 5": "signingTime",
	"1 2 840 113549 1 9 16 2 47": "signingCertificateV2",
	"1 2 840 113549 1 9 16 2 20": "contentTimeStamp",
	"1 2 840 113549 1 9 16 2 14": "timeStampToken",
	"1 2 840 113549 1 9 16 2 21": "certificateRefs",
	"1 2 840 113549 1 9 16 2 22": "revocationRefs",
	"1 2 840 113549 1 9 16 2 23": "certificateValues",
	"1 2 840 113549 1 9 16 2 24": "revocationValues",
	"2 5 4 3": "commonName",
	"2 5 4 4": "surname",
	"2 5 4 5": "serialNumber",
	"2 5 4 6": "countryName",
	"2 5 4 7": "localityName",
	"2 5 4 8": "stateOrProvinceName",
	"2 5 4 9": "streetAddress",
	"2 5 4 10": "organizationName",
	"2 5 4 11": "organizationalUnitName",
	"2 5 4 12": "title",
	"2 5 4 13": "description",
	"2 5 4 14": "searchGuide",
	"2 5 4 15": "businessCategory",
	"2 5 4 16": "postalAddress",
	"2 5 4 17": "postalCode",
	"2 5 4 18": "postOfficeBox",
	"2 5 4 19": "physicalDeliveryOfficeName",
	"2 5 4 20": "telephoneNumber",
	"2 5 4 21": "telexNumber",
	"2 5 4 22": "teletexTerminalIdentifier",
	"2 5 4 23": "facsimileTelephoneNumber",
	"2 5 4 24": "x121Address",
	"2 5 4 25": "internationaliSDNNumber",
	"2 5 4 26": "registeredAddress",
	"2 5 4 27": "destinationIndicator",
	"2 5 4 28": "preferredDeliveryMethod",
	"2 5 4 29": "presentationAddress",
	"2 5 4 30": "supportedApplicationContext",
	"2 5 4 31": "member",
	"2 5 4 32": "owner",
	"2 5 4 33": "roleOccupant",
	"2 5 4 34": "seeAlso",
	"2 5 4 35": "userPassword",
	"2 5 4 36": "userCertificate",
	"2 5 4 37": "cACertificate",
	"2 5 4 38": "authorityRevocationList",
	"2 5 4 39": "certificateRevocationList",
	"2 5 4 40": "crossCertificatePair",
	"2 5 4 41": "name",
	"2 5 4 42": "givenName",
	"2 5 4 43": "initials",
	"2 5 4 44": "generationQualifier",
	"2 5 4 45": "x500UniqueIdentifier",
	"2 5 4 46": "dnQualifier",
	"2 5 4 47": "enhancedSearchGuide",
	"2 5 4 48": "protocolInformation",
	"2 5 4 49": "distinguishedName",
	"2 5 4 50": "uniqueMember",
	"2 5 4 51": "houseIdentifier",
	"2 5 4 52": "supportedAlgorithms",
	"2 5 4 53": "deltaRevocationList",
	"2 5 4 54": "dmdName",
	"2 5 4 65": "pseudonym",
	"2 5 4 72": "role",
	"2 5 4 97": "organizationIdentifier"
};
var AttributeType = asn1_js.default.define("AttributeType", function() {
	this.objid(AttributeObjId);
});
var AttributeValue = asn1_js.default.define("AttributeValue", function() {
	this.any();
});
var KeyPurposeIdMap = {
	"1 3 6 1 5 5 7 3 8": "timeStamping",
	"1 3 6 1 5 5 7 3 9": "ocspSigning"
};
var KeyPurposeId = asn1_js.default.define("KeyPurposeId", function() {
	this.objid(KeyPurposeIdMap);
});
var ExtKeyUsageSyntax = asn1_js.default.define("ExtKeyUsageSyntax", function() {
	this.seqof(KeyPurposeId);
});
var BasicConstraints = asn1_js.default.define("BasicConstraints", function() {
	this.seq().obj(this.key("cA").bool().def(false), this.key("pathLenConstraint").int().optional());
});
function injectPubAlgo(algo, paramSpec) {
	PUBKEY_PARAMS[algo] = paramSpec;
}
//#endregion
//#region lib/spec/dstszi2010.js
var dstszi2010_exports = /* @__PURE__ */ __exportAll({
	Attributes: () => Attributes,
	ContentEncryptionAlgorithmIdentifier: () => ContentEncryptionAlgorithmIdentifier,
	ContentInfo: () => ContentInfo$2,
	ContentType: () => ContentType,
	DEFAULT_SBOX_COMPRESSED: () => DEFAULT_SBOX_COMPRESSED,
	Data: () => Data,
	IssuerAndSerialNumber: () => IssuerAndSerialNumber,
	PKCS7_CONTENT_TYPES: () => PKCS7_CONTENT_TYPES,
	SharedInfo: () => SharedInfo
});
/**
http://tools.ietf.org/html/rfc2315#section-14

pkcs-7 OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) US(840) rsadsi(113549)
pkcs(1) 7 }

data OBJECT IDENTIFIER ::= { pkcs-7 1 }
signedData OBJECT IDENTIFIER ::= { pkcs-7 2 }
envelopedData OBJECT IDENTIFIER ::= { pkcs-7 3 }
signedAndEnvelopedData OBJECT IDENTIFIER ::=
{ pkcs-7 4 }
digestedData OBJECT IDENTIFIER ::= { pkcs-7 5 }
encryptedData OBJECT IDENTIFIER ::= { pkcs-7 6 }
*/
const PKCS7_CONTENT_TYPES = {
	"1 2 840 113549 1 7 1": "data",
	"1 2 840 113549 1 7 2": "signedData",
	"1 2 840 113549 1 7 3": "envelopedData",
	"1 2 840 113549 1 7 4": "signedAndEnvelopedData",
	"1 2 840 113549 1 7 5": "digestData",
	"1 2 840 113549 1 7 6": "encryptedData",
	"1 2 840 113549 1 9 16 1 4": "tstInfo"
};
var ContentType = asn1_js.default.define("ContentType", function() {
	this.objid(PKCS7_CONTENT_TYPES);
});
/**
http://tools.ietf.org/html/rfc2315#section-7

ContentInfo ::= SEQUENCE {
contentType ContentType,
content
[0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
*/
var ContentInfo$2 = asn1_js.default.define("ContentInfo", function() {
	this.seq().obj(this.key("contentType").use(ContentType), this.key("content").optional().explicit(0).use(function(obj) {
		var model = ContentInfo$2.contentModel[obj.contentType];
		if (model === void 0) throw new Error("Can't parse " + obj.contentType + " in PKCS#7");
		return model;
	}));
});
/**
DSTU GOST 28147:2009

TODO missing
*/
var GOST28147Parameters = asn1_js.default.define("GOST28147Parameters", function() {
	this.seq().obj(this.key("iv").octstr(), this.key("dke").optional().octstr());
});
/**
http://tools.ietf.org/html/rfc2315#section-6.2

ContentEncryptionAlgorithmIdentifier ::=
AlgorithmIdentifier

http://tools.ietf.org/html/rfc3280#section-4.1.1.2

AlgorithmIdentifier  ::=  SEQUENCE  {
algorithm               OBJECT IDENTIFIER,
parameters              ANY DEFINED BY algorithm OPTIONAL  }


DSTU GOST 28147:2009
TODO missing

*/
var ContentEncryptionAlgorithmIdentifier = asn1_js.default.define("ContentEncryptionAlgorithmIdentifier", function() {
	this.seq().obj(this.key("algorithm").objid(ContentInfo$2.algoModel.IDS), this.key("parameters").choice({
		null_: this.null_(),
		params: this.use(function(obj) {
			const ret = ContentInfo$2.algoModel[obj.algorithm];
			if (!ret) throw new Error("No spec for", obj.algorithm);
			return ret;
		})
	}));
});
var DigestAlgorithmIdentifier = asn1_js.default.define("DigestAlgorithmIdentifier", function() {
	this.use(AlgorithmIdentifier);
});
var DigestAlgorithmIdentifiers = asn1_js.default.define("DigestAlgorithmIdentifiers", function() {
	this.setof(DigestAlgorithmIdentifier);
});
var KeyEncryptionAlgorithmIdentifier = asn1_js.default.define("KeyEncryptionAlgorithmIdentifier", function() {
	this.seq().obj(this.key("algorithm").objid(ALGORITHMS_IDS), this.key("parameters").use(WrapAlgo));
});
/**
http://tools.ietf.org/html/rfc2315#section-6.7

IssuerAndSerialNumber ::= SEQUENCE {
issuer Name,
serialNumber CertificateSerialNumber }

*/
var IssuerAndSerialNumber = asn1_js.default.define("IssuerAndSerialNumber", function() {
	this.seq().obj(this.key("issuer").use(Name), this.key("serialNumber").use(CertificateSerialNumber$1));
});
/**
Attribute: A type that contains an attribute type (specified by
object identifier) and one or more attribute values. This type is
defined in X.501.

Attribute ::= SEQUENCE {
type AttributeType ( { SupportedAttributes } ),
values SET SIZE (1 .. MAX) OF AttributeValue ( { SupportedAttributes}{@type})}

*/
var Attribute = asn1_js.default.define("Attribute", function() {
	this.seq().obj(this.key("type").use(AttributeType), this.key("values").setof(AttributeValue));
});
var Attributes = asn1_js.default.define("Attributes", function() {
	this.setof(Attribute);
});
var DigestEncryptionAlgorithmIdentifier = asn1_js.default.define("DigestEncryptionAlgorithmIdentifier", function() {
	this.use(AlgorithmIdentifier);
});
var SubjectKeyIdentifier = asn1_js.default.define("SubjectKeyIdentifier", function() {
	this.octstr();
});
var SignerIdentifier = asn1_js.default.define("SignerIdentifier", function() {
	this.choice({
		issuerAndSerialNumber: this.use(IssuerAndSerialNumber),
		subjectKeyIdentifier: this.explicit(0).use(SubjectKeyIdentifier)
	});
});
/**

http://www.ietf.org/rfc/rfc3852.txt

SignerInfo ::= SEQUENCE {
version Version,
sid SignerIdentifier,
digestAlgorithm DigestAlgorithmIdentifier,
authenticatedAttributes
[0] IMPLICIT Attributes OPTIONAL,
digestEncryptionAlgorithm
DigestEncryptionAlgorithmIdentifier,
encryptedDigest EncryptedDigest,
unauthenticatedAttributes
[1] IMPLICIT Attributes OPTIONAL }

*/
var SignerInfo = asn1_js.default.define("SignerInfo", function() {
	this.seq().obj(this.key("version").int(), this.key("sid").use(SignerIdentifier), this.key("digestAlgorithm").use(DigestAlgorithmIdentifier), this.key("authenticatedAttributes").optional().implicit(0).use(Attributes), this.key("digestEncryptionAlgorithm").use(DigestEncryptionAlgorithmIdentifier), this.key("encryptedDigest").octstr(), this.key("unauthenticatedAttributes").optional().implicit(1).use(Attributes));
});
var SignerInfos = asn1_js.default.define("SignerInfos", function() {
	this.setof(SignerInfo);
});
var Certificates = asn1_js.default.define("Certificates", function() {
	this.seqof(Certificate$1);
});
/**
http://tools.ietf.org/html/rfc2315#section-9.1

SignedData ::= SEQUENCE {
version Version,
digestAlgorithms DigestAlgorithmIdentifiers,
contentInfo ContentInfo,
certificates
[0] IMPLICIT ExtendedCertificatesAndCertificates
OPTIONAL,
crls
[1] IMPLICIT CertificateRevocationLists OPTIONAL,
signerInfos SignerInfos }
*/
var SignedData = asn1_js.default.define("SignedData", function() {
	this.seq().obj(this.key("version").int(), this.key("digestAlgorithms").use(DigestAlgorithmIdentifiers), this.key("contentInfo").use(ContentInfo$2), this.key("certificate").optional().implicit(0).use(Certificates), this.key("crls").optional().implicit(1).set(), this.key("signerInfos").use(SignerInfos));
});
var RecipientKeyIdentifier = asn1_js.default.define("RecipientKeyIdentifier", function() {
	this.seq().obj(this.key("subjectKeyIdentifier").octstr(), this.key("date").use(Time).optional(), this.key("other").optional().any());
});
var KeyAgreeRecipientIdentifier = asn1_js.default.define("KeyAgreeRecipientIdentifier", function() {
	this.choice({
		issuerAndSerialNumber: this.use(IssuerAndSerialNumber),
		rKeyId: this.implicit(0).use(RecipientKeyIdentifier)
	});
});
var RecipientEncryptedKey = asn1_js.default.define("RecipientEncryptedKey", function() {
	this.seq().obj(this.key("rid").use(KeyAgreeRecipientIdentifier), this.key("encryptedKey").octstr());
});
asn1_js.default.define("OriginatorInfo", function() {
	this.seq().obj(this.key("certificates").use(IssuerAndSerialNumber));
});
var OriginatorPublicKey = asn1_js.default.define("OriginatorPublicKey", function() {
	this.seq().obj(this.key("algorithm").use(AlgorithmIdentifier), this.key("publicKey").bitstr());
});
var OriginatorIdentifierOrKey = asn1_js.default.define("OriginatorIdentifierOrKey", function() {
	this.seq().choice({
		issuerAndSerialNumber: this.use(IssuerAndSerialNumber),
		subjectKeyIdentifier: this.implicit(0).use(SubjectKeyIdentifier),
		originatorKey: this.implicit(1).use(OriginatorPublicKey)
	});
});
/**
https://tools.ietf.org/html/rfc5652#section-6.2

RecipientInfo ::= SEQUENCE {
version Version,
issuerAndSerialNumber IssuerAndSerialNumber,
keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
encryptedKey EncryptedKey }

EncryptedKey ::= OCTET STRING

*/
var KeyAgreeRecipientInfo = asn1_js.default.define("KeyAgreeRecipientInfo", function() {
	this.seq().obj(this.key("version").int(), this.key("originator").explicit(0).use(OriginatorIdentifierOrKey), this.key("ukm").explicit(1).octstr(), this.key("keyEncryptionAlgorithm").use(KeyEncryptionAlgorithmIdentifier), this.key("recipientEncryptedKeys").seqof(RecipientEncryptedKey));
});
var RecipientInfo = asn1_js.default.define("RecipientInfo", function() {
	this.choice({ kari: this.implicit(1).use(KeyAgreeRecipientInfo) });
});
/**
http://tools.ietf.org/html/rfc2315#section-10.1

EncryptedContentInfo ::= SEQUENCE {
contentType ContentType,
contentEncryptionAlgorithm
ContentEncryptionAlgorithmIdentifier,
encryptedContent
[0] IMPLICIT EncryptedContent OPTIONAL }

EncryptedContent ::= OCTET STRING

*/
var EncryptedContentInfo = asn1_js.default.define("EncryptedContentInfo", function() {
	this.seq().obj(this.key("contentType").objid(PKCS7_CONTENT_TYPES), this.key("contentEncryptionAlgorithm").use(ContentEncryptionAlgorithmIdentifier), this.key("encryptedContent").optional().implicit(0).octstr());
});
/**
http://tools.ietf.org/html/rfc2315#section-10.1

EnvelopedData ::= SEQUENCE {
version Version,
recipientInfos RecipientInfos,
encryptedContentInfo EncryptedContentInfo }
*/
var EnvelopedData = asn1_js.default.define("EnvelopedData", function() {
	this.seq().obj(this.key("version").int(), this.key("recipientInfos").setof(RecipientInfo), this.key("encryptedContentInfo").use(EncryptedContentInfo));
});
/**
https://www.rfc-editor.org/rfc/rfc2315#section-13

EncryptedData ::= SEQUENCE {
version Version,
encryptedContentInfo EncryptedContentInfo }
*/
var EncryptedData = asn1_js.default.define("EncryptedData", function() {
	this.seq().obj(this.key("version").int(), this.key("encryptedContentInfo").use(EncryptedContentInfo));
});
var Data = asn1_js.default.define("Data", function() {
	this.octstr();
});
ContentInfo$2.contentModel = {
	signedData: SignedData,
	envelopedData: EnvelopedData,
	encryptedData: EncryptedData,
	data: Data
};
ContentInfo$2.algoModel = { "Gost28147-cfb": GOST28147Parameters };
ContentInfo$2.algoModel.IDS = Object.assign({}, ALGORITHMS_IDS);
var WrapAlgo = asn1_js.default.define("WrapAlgo", function() {
	this.seq().obj(this.key("algorithm").objid(ALGORITHMS_IDS), this.key("parameters").null_());
});
var SharedInfo = asn1_js.default.define("SharedInfo", function() {
	this.seq().obj(this.key("keyInfo").use(WrapAlgo), this.key("entityInfo").optional().explicit(0).octstr(), this.key("suppPubInfo").explicit(2).octstr());
});
function packSbox(input) {
	const ret = buffer.Buffer.alloc(input.length / 2);
	const rows = input.length & 240;
	for (let idx = 0; idx < input.length; idx += 2) {
		let retIdx = rows - 16 - (idx & 240) | idx & 15;
		ret[retIdx >> 1] = input[idx] << 4 | input[idx + 1];
	}
	return ret;
}
const DEFAULT_SBOX_COMPRESSED = packSbox(buffer.Buffer.from("0102030E060D0B080F0A0C050709000403080B0506040E0A020C0107090F0D0002080907050F000B0C010D0E0A0306040F080E090702000D0C0601050B04030A03080D09060B0F0002050C0A040E01070F0605080E0B0A040C0003070209010D08000C040906070B0203010F050E0A0D0A090D060E0B04050F01030C07000802", "hex"));
//#endregion
//#region lib/spec/pbes.js
const CipherParams = ContentEncryptionAlgorithmIdentifier;
const ContentInfo$1 = ContentInfo$2;
var OID$3 = {
	"1 2 840 113549 1 5 13": "PBES2",
	"1 2 840 113549 1 5 12": "PBKDF2"
};
var PBKDF2_params = asn1_js.default.define("PBKDF2-params", function() {
	this.seq().obj(this.key("salt").octstr(), this.key("cycles").int(), this.key("keyLength").optional().int(), this.key("hash").use(CipherParams));
});
var PBES2_params = asn1_js.default.define("PBES2-params", function() {
	this.seq().obj(this.key("keyDerivationFunc").seq().obj(this.key("id").objid(OID$3), this.key("params").use(PBKDF2_params)), this.key("encryptionScheme").use(CipherParams));
});
var PBES2Algorithms = asn1_js.default.define("PBES2Algorithms", function() {
	this.seq().obj(this.key("algorithm").objid(OID$3), this.key("parameters").choice({
		null_: this.null_(),
		params: this.use(PBES2_params)
	}));
});
var PBES2 = asn1_js.default.define("StorePBES2", function() {
	this.seq().obj(this.key("contentEncryptionAlgorithm").use(PBES2Algorithms), this.key("encryptedContent").octstr());
});
Object.assign(ContentInfo$1.algoModel.IDS, OID$3);
Object.assign(ContentInfo$1.algoModel, { PBES2: PBES2_params });
var pbes2_parse = function(data) {
	return [pbes2_parse_asn1(PBES2.decode(data, "der"))];
};
var pbes2_parse_asn1 = function(asn1) {
	var kdf, enc, params, iv, sbox, salt, iter;
	if (asn1.contentEncryptionAlgorithm.algorithm !== "PBES2") throw new Error(asn1.contentEncryptionAlgorithm.algorithm);
	if (asn1.contentEncryptionAlgorithm.parameters.type !== "params") throw new Error(asn1.contentEncryptionAlgorithm.parameters.type);
	kdf = asn1.contentEncryptionAlgorithm.parameters.value.keyDerivationFunc;
	if (kdf.id !== "PBKDF2") throw new Error(kdf.id);
	if (kdf.params.hash.algorithm !== "Gost34311-hmac") throw new Error("Unknown cipher " + kdf.params.hash.algorithm);
	enc = asn1.contentEncryptionAlgorithm.parameters.value.encryptionScheme;
	if (enc.algorithm !== "Gost28147-cfb") throw new Error(enc.algorithm);
	params = enc.parameters.value;
	if (params === null) throw new Error("Encryption params not passed");
	iv = params.iv;
	sbox = params.dke;
	salt = kdf.params.salt;
	iter = kdf.params.cycles;
	if (iv.length !== 8 || sbox.length !== 64 || salt.length !== 32) throw new Error("IV len: " + iv.length + ", S-BOX len: " + sbox.length + ", SALT len: " + salt.length);
	return {
		format: "PBES2",
		iv,
		sbox,
		salt,
		iters: iter.toNumber(),
		body: asn1.encryptedContent
	};
};
var pbes2_serialize = function(store) {
	return PBES2.encode({
		contentEncryptionAlgorithm: {
			algorithm: "PBES2",
			parameters: {
				type: "params",
				value: {
					keyDerivationFunc: {
						id: "PBKDF2",
						params: {
							salt: store.salt,
							cycles: 1e4,
							hash: {
								algorithm: "Gost34311-hmac",
								parameters: {
									type: "null_",
									value: null
								}
							}
						}
					},
					encryptionScheme: {
						algorithm: "Gost28147-cfb",
						parameters: {
							type: "params",
							value: {
								iv: store.iv,
								dke: store.sbox
							}
						}
					}
				}
			}
		},
		encryptedContent: store.body
	}, "der");
};
PBES2.obj_parse = pbes2_parse_asn1;
PBES2.pbes2_parse = pbes2_parse;
//#endregion
//#region lib/spec/pfx.js
const OID$2 = {
	"1 2 840 113549 1 12 10 1 2": "pkcs-12-pkcs-8ShroudedKeyBag",
	"1 2 840 113549 1 12 10 1 3": "pkcs-12-certBag",
	"1 2 840 113549 1 12 10 1 5": "secretBag"
};
const BagModels = {
	"pkcs-12-pkcs-8ShroudedKeyBag": PBES2,
	"pkcs-12-certBag": asn1_js.default.define("CertBag", function() {
		this.seq().obj(this.key("id").objid({ "1 2 840 113549 1 9 22 1": "x509Certificate" }), this.key("certValue").explicit(0).octstr());
	}),
	secretBag: asn1_js.default.define("SecretBag", function() {
		this.seq().obj(this.key("id").objid(PKCS7_CONTENT_TYPES), this.key("content").any());
	})
};
const SafeBag = asn1_js.default.define("SafeContents", function() {
	this.seq().obj(this.key("bagId").objid(OID$2), this.key("bagValue").explicit(0).use(function(ob) {
		if (!BagModels[ob.bagId]) throw new Error("Unknown bag id", ob.bagId);
		return BagModels[ob.bagId];
	}), this.key("bagAttributes").set().optional());
});
const SafeContents = asn1_js.default.define("SafeContents", function() {
	return this.seqof(SafeBag);
});
const Bags = asn1_js.default.define("ContentInfo", function() {
	this.seqof(ContentInfo$2);
});
function pfx_parse_helper(data, offset) {
	return Bags.decode(data.slice(offset), "der").filter((msg) => msg.contentType === "data" || msg.contentType === "encryptedData").map((msg) => {
		if (msg.contentType === "encryptedData") return PBES2.obj_parse(msg.content.encryptedContentInfo);
		return SafeContents.decode(msg.content, "der").filter((bag) => bag.bagId === "pkcs-12-pkcs-8ShroudedKeyBag").map((bag) => PBES2.obj_parse(bag.bagValue));
	}).reduce((acc, keys) => acc.concat(keys), []);
}
function pfx_parse(data) {
	const known_offsets = [30, 34];
	let pos = 0;
	while (known_offsets.length) {
		pos = known_offsets.pop();
		try {
			return pfx_parse_helper(data, pos);
		} catch (e) {
			continue;
		}
	}
}
function certbags_from_asn1(data) {
	return SafeContents.decode(data, "der").map((bag) => bag.bagValue.certValue);
}
//#endregion
//#region lib/spec/keystore.js
var OID$1 = {
	"1 2 804 2 1 1 1 1 3 1 1": "DSTU_4145_LE",
	"1 3 6 1 4 1 19398 1 1 2 3": "DSTU_4145_KEY_BITS",
	"1 3 6 1 4 1 19398 1 1 2 2": "DSTU_4145_CURVE"
};
var KeyAttrValue = asn1_js.default.define("KeyAttrValue", function() {
	this.choice({
		param_d: this.bitstr(),
		dstu4145: this.use(DstuParams),
		unknown: this.any()
	});
});
var KeyAttrValues = asn1_js.default.define("KeyAttrValues", function() {
	this.setof(KeyAttrValue);
});
var KeyAttr = asn1_js.default.define("Attr", function() {
	this.seq().obj(this.key("id").objid(OID$1), this.key("value").use(KeyAttrValues));
});
var Pentanominal = asn1_js.default.define("Pentanominal", function() {
	this.seq().obj(this.key("k1").int(), this.key("k2").int(), this.key("k3").int());
});
var Polynomial = asn1_js.default.define("Polynomial", function() {
	this.choice({
		trinominal: this.int(),
		pentanominal: this.use(Pentanominal)
	});
});
var CurveParams = asn1_js.default.define("CurveParams", function() {
	this.seq().obj(this.key("p").seq().obj(this.key("param_m").int(), this.key("ks").use(Polynomial)), this.key("param_a").int(), this.key("param_b").octstr(), this.key("order").int(), this.key("bp").octstr());
});
var CURVES = {
	"1 2 804 2 1 1 1 1 3 1 1 2 0": "DSTU_PB_163",
	"1 2 804 2 1 1 1 1 3 1 1 2 1": "DSTU_PB_167",
	"1 2 804 2 1 1 1 1 3 1 1 2 2": "DSTU_PB_173",
	"1 2 804 2 1 1 1 1 3 1 1 2 3": "DSTU_PB_179",
	"1 2 804 2 1 1 1 1 3 1 1 2 4": "DSTU_PB_191",
	"1 2 804 2 1 1 1 1 3 1 1 2 5": "DSTU_PB_233",
	"1 2 804 2 1 1 1 1 3 1 1 2 6": "DSTU_PB_257",
	"1 2 804 2 1 1 1 1 3 1 1 2 7": "DSTU_PB_307",
	"1 2 804 2 1 1 1 1 3 1 1 2 8": "DSTU_PB_367",
	"1 2 804 2 1 1 1 1 3 1 1 2 9": "DSTU_PB_431",
	"1 2 840 10045 3 1 7": "secp256r1"
};
var Curve$1 = asn1_js.default.define("Curve", function() {
	this.choice({
		id: this.objid(CURVES),
		params: this.use(CurveParams)
	});
});
var DstuParams = asn1_js.default.define("CurveParams", function() {
	this.seq().obj(this.key("curve").use(Curve$1), this.key("dke").optional().octstr(), this.key("dke2").optional().octstr());
});
injectPubAlgo("Dstu4145le", DstuParams);
injectPubAlgo("ECDSA", Curve$1);
var DstuPrivkey = asn1_js.default.define("DstuPrivkey", function() {
	this.seq().obj(this.key("version").int(), this.key("priv0").seq().obj(this.key("id").objid(OID$1), this.key("p").seq().obj(this.key("p").use(Curve$1), this.key("sbox").optional().octstr())), this.key("param_d").octstr(), this.key("attr").optional().implicit(0).seqof(KeyAttr));
});
var StoreIIT = asn1_js.default.define("StoreIIT", function() {
	this.seq().obj(this.key("cryptParam").seq().obj(this.key("cryptType").objid({
		"1 3 6 1 4 1 19398 1 1 1 2": "IIT Store",
		"1 2 840 113549 1 5 13": "PBES2",
		"1 2 840 113549 1 5 12": "PBKDF2",
		"1 2 804 2 1 1 1 1 1 2": "GOST_34311_HMAC",
		"1 2 804 2 1 1 1 1 1 1 3": "GOST_28147_CFB",
		"1 2 804 2 1 1 1 1 3 1 1": "DSTU_4145_LE"
	}), this.key("cryptParam").seq().obj(this.key("mac").octstr(), this.key("pad").octstr().optional())), this.key("cryptData").octstr());
});
var enc_parse = function(data) {
	var asn1 = StoreIIT.decode(data, "der"), mac = asn1.cryptParam.cryptParam.mac, pad = asn1.cryptParam.cryptParam.pad;
	if (mac.length !== 4) throw new Error("Invalid mac len " + mac.length);
	if (pad.length >= 8) throw new Error("Invalid pad len " + pad.length);
	if (asn1.cryptParam.cryptType !== "IIT Store") throw new Error("Invalid storage type");
	return {
		format: "IIT",
		mac,
		pad,
		body: asn1.cryptData
	};
};
var enc_parse_many = function(data) {
	return [enc_parse(data)];
};
//#endregion
//#region lib/models/Pub.js
var Pub = class Pub {
	constructor(p_curve, point_q, compressed) {
		this.x = point_q.x;
		this.y = point_q.y;
		this.point = point_q;
		this.curve = p_curve;
		this._cmp = compressed && new Field(compressed, "buf32", this.curve);
		this.type = "Pub";
	}
	compress() {
		if (!this._cmp) this._cmp = this.point.compress();
		return this._cmp.buf8();
	}
	verify(hash_val, sign, fmt) {
		if (fmt === void 0) fmt = Pub.detect_sign_format(sign);
		if (buffer.Buffer.isBuffer(hash_val)) hash_val = new Field(add_zero(hash_val, true), "buf8", this.curve);
		sign = Pub.parse_sign(sign, fmt, this.curve);
		return this.help_verify(hash_val, sign.s, sign.r);
	}
	help_verify(hash_val, s, r) {
		if (s.is_zero()) throw new Error("Invalid sig component S");
		if (r.is_zero()) throw new Error("Invalid sig component R");
		if (this.curve.order.less(s)) throw new Error("Invalid sig component S");
		if (this.curve.order.less(r) < 0) throw new Error("Invalid sig component R");
		const mulQ = this.point.mul(r);
		const pointR = this.curve.base.mul(s).add(mulQ);
		if (pointR.is_zero()) throw new Error("Invalid sig R point at infinity");
		let r1 = pointR.x.mod_mul(this.curve.truncate(hash_val));
		r1 = this.curve.truncateTo(r1, this.curve.order.bitLength() - 1);
		return r.equals(r1);
	}
	validate() {
		const pub_q = this.point;
		const pt = pub_q.mul(this.curve.order);
		if (pub_q.is_zero() || !this.curve.contains(pub_q) || !pt.is_zero()) return false;
		return true;
	}
	serialize() {
		const buf = this.compress();
		const cut = buf.length - Math.ceil(this.curve.m / 8);
		const inverse = buffer.Buffer.alloc(buf.length + 2 - cut);
		for (let i = 2; i < inverse.length; i++) inverse[i] = buf[buf.length + 1 - i];
		inverse[0] = 4;
		inverse[1] = buf.length - cut;
		return inverse;
	}
	keyid(algos) {
		return algos.hash(this.serialize());
	}
	static detect_format(inp) {
		if (is_hex(inp)) return "hex";
		if (inp.buffer !== void 0) return "raw";
		throw new Error("Unknown pubkey format");
	}
	static detect_sign_format(sign) {
		if (sign.hasOwnProperty && sign.hasOwnProperty("s") && sign.hasOwnProperty("r")) return "split";
		if (typeof sign === "string" || buffer.Buffer.isBuffer(sign)) return "short";
	}
	static parse_sign(sign, fmt, curve) {
		if (fmt === "short") {
			if (!buffer.Buffer.isBuffer(sign)) sign = buffer.Buffer.from(sign);
			if (sign[0] !== 4 || sign[1] !== sign.length - 2) throw new Error("Broken short sign");
			sign = sign.slice(2);
			fmt = "le";
		}
		if (fmt === "le") {
			const len = sign.length;
			const r = sign.slice(0, Math.ceil(len / 2));
			sign = {
				s: add_zero(sign.slice(r.length), true),
				r: add_zero(r, true)
			};
			fmt = "split";
		}
		if (fmt === "split") {
			if (typeof sign.s === "string") sign.s = buffer.Buffer.from(sign.s);
			if (typeof sign.r === "string") sign.r = buffer.Buffer.from(sign.r);
			return {
				s: new Field(sign.s, "buf8", curve),
				r: new Field(sign.r, "buf8", curve)
			};
		}
	}
};
//#endregion
//#region lib/models/Priv.js
const bn$1 = asn1_js.default.bignum;
function gost_salt(ukm) {
	return SharedInfo.encode({
		keyInfo: {
			algorithm: "Gost28147-cfb-wrap",
			parameters: null
		},
		entityInfo: ukm || void 0,
		suppPubInfo: buffer.Buffer.from("\0\0\0", "binary")
	}, "der");
}
function detect_format(inp) {
	if (is_hex(inp) === true) return "hex";
	throw new Error("Unknown privkey format");
}
function attr_parse(attr) {
	const ahash = {};
	let aob, priv1_d, dstu, curve;
	for (let i = 0; i < attr.length; i++) {
		aob = attr[i];
		if (aob.id !== void 0) ahash[aob.id] = aob.value[0].value;
	}
	if (!ahash.DSTU_4145_KEY_BITS) return;
	if (ahash.DSTU_4145_CURVE === void 0) return;
	priv1_d = ahash.DSTU_4145_KEY_BITS.data;
	dstu = ahash.DSTU_4145_CURVE;
	if (priv1_d === void 0 || priv1_d.length === 0) return;
	curve = Curve.resolve(dstu.curve);
	return curve.pkey(BIG_INVERT(priv1_d), "buf8");
}
function curve_params(p) {
	return new Curve({
		m: p.p.param_m,
		ks: Curve.ks_parse(p.p.ks),
		a: [p.param_a],
		b: BIG_LE(p.param_b),
		order: BIG_BE(p.order.toArray()),
		kofactor: [4 >> p.param_a],
		base: BIG_LE(p.bp)
	});
}
function from_asn1(data, return_store) {
	let key0, key1, priv, curve;
	priv = DstuPrivkey.decode(data, "der");
	const params = priv.priv0.p.p;
	curve = params.type === "id" ? std_curve(params.value) : curve_params(params.value);
	key0 = curve.pkey(BIG_LE(priv.param_d), "buf32");
	key0.sbox = priv.priv0.p.sbox;
	if (return_store !== true) return key0;
	key1 = priv.attr && attr_parse(priv.attr);
	return {
		keys: key1 ? [key0, key1] : [key0],
		format: "privkeys"
	};
}
function short_sign(sign, raw) {
	const tmp_s = sign.s.truncate_buf8();
	const tmp_r = sign.r.truncate_buf8();
	const mlen = Math.max(tmp_s.length, tmp_r.length);
	const sbuf = buffer.Buffer.alloc(2 + mlen * 2);
	sbuf.writeUInt8(4, 0);
	sbuf.writeUInt8(mlen * 2, 1);
	for (let idx = 0; idx < mlen; idx++) {
		const tmp = tmp_r[mlen - idx - 1];
		sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2);
	}
	for (let idx = 0; idx < mlen; idx++) {
		const tmp = tmp_s[mlen - idx - 1];
		sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2 + mlen);
	}
	if (raw) return sbuf.slice(2);
	return sbuf;
}
function sign_serialise(data, fmt) {
	if (fmt === "short" || fmt === "le") return short_sign(data, fmt === "le");
	throw new Error("Unkown signature format " + fmt);
}
var Priv = class {
	constructor(p_curve, param_d) {
		this.type = "Priv";
		this.d = param_d._is_field ? param_d : new Field(param_d, "bn", p_curve);
		this.curve = p_curve;
		this.algorithm = "Dstu4145le";
	}
	help_sign(hash_v, rand_e) {
		const eG = this.curve.base.mul(rand_e);
		if (eG.x.is_zero()) return null;
		hash_v = this.curve.truncate(hash_v);
		let r = hash_v.mod_mul(eG.x);
		if (r.is_zero()) return null;
		const big_d = new bn$1.BN(this.d.buf8(), 8);
		const big_rand_e = new bn$1.BN(rand_e.buf8(), 8);
		const big_order = new bn$1.BN(this.curve.order.buf8(), 8);
		const l = this.curve.order.bitLength() - 1;
		const modL = new bn$1.BN(1).shln(l);
		r = new bn$1.BN(r.buf8(), 8).mod(modL);
		let s = big_d.mul(r).mod(big_order);
		s = s.add(big_rand_e).mod(big_order);
		if (s.cmpn(0) === 0) return null;
		return {
			s: new Field(s.toArray(), "buf8", this.curve),
			r: new Field(r.toArray(), "buf8", this.curve)
		};
	}
	sign(hash_buf, fmt) {
		let rand_e, ret, hash_v;
		if (buffer.Buffer.isBuffer(hash_buf)) hash_v = new Field(add_zero(hash_buf, true), "buf8", this.curve);
		else throw new Error("not a buffer");
		if (hash_v.is_zero()) throw new Error("Pass non zero value");
		while (true) {
			rand_e = this.curve.rand();
			ret = this.help_sign(hash_v, rand_e);
			if (ret !== null) break;
		}
		ret.hash = hash_v;
		if (fmt === void 0) return ret;
		return sign_serialise(ret, fmt);
	}
	decrypt(data, pubkey, param, algo) {
		if (pubkey.pubkey) pubkey = pubkey.pubkey;
		const kek = this.sharedKey(pubkey, param.ukm, algo.kdf);
		const cek = algo.keyunwrap(kek, param.wcek);
		return algo.decrypt(data, cek, param.iv);
	}
	encrypt(data, cert, algo) {
		global.crypto;
		const cek = rand_default(buffer.Buffer.alloc(32));
		const ukm = rand_default(buffer.Buffer.alloc(64));
		const iv = rand_default(buffer.Buffer.alloc(8));
		const kek = this.sharedKey(cert.pubkey, ukm, algo.kdf);
		return {
			iv,
			wcek: algo.keywrap(kek, cek, iv),
			data: algo.encrypt(data, cek, iv),
			ukm
		};
	}
	pub_match(pub_key) {
		let check_key = null;
		if (pub_key.type === "Pub") return pub_key.point.equals(this.pub().point);
		if (pub_key._is_field) check_key = pub_key;
		if (buffer.Buffer.isBuffer(pub_key)) check_key = new Field(pub_key, "buf8", this.curve);
		if (check_key === null) throw new Error("Unknow pubkey format");
		return check_key.equals(this.pub_compress());
	}
	pub_compress() {
		if (this._pub === void 0) this._pub = this.pub();
		if (this._pub_cmp === void 0) this._pub_cmp = this._pub.point.compress();
		return this._pub_cmp;
	}
	pub() {
		return new Pub(this.curve, this.curve.base.mul(this.d).negate());
	}
	derive(pubkey) {
		let pointQ, pointZ, bufZZ, cut;
		if (pubkey.type === "Pub") pointQ = pubkey.point;
		else pointQ = this.curve.point(pubkey);
		pointZ = pointQ.mul(this.d.mod_mul(this.curve.kofactor));
		bufZZ = buffer.Buffer.from(pointZ.x.buf8(), "binary");
		cut = bufZZ.length - Math.ceil(this.curve.m / 8);
		return bufZZ.slice(cut);
	}
	sharedKey(pubkey, ukm, kdf) {
		let zz = this.derive(pubkey);
		if (zz[0] === 0) zz = zz.slice(1);
		const counter = buffer.Buffer.from("\0\0\0", "binary");
		const salt = gost_salt(ukm);
		const kek_input = buffer.Buffer.alloc(zz.length + counter.length + salt.length);
		zz.copy(kek_input);
		counter.copy(kek_input, zz.length);
		salt.copy(kek_input, zz.length + counter.length);
		return kdf(kek_input);
	}
	as_pem() {
		return "-----BEGIN PRIVATE KEY-----\n" + b64_encode(this.as_asn1(), {
			line: 16,
			pad: true
		}) + "\n-----END PRIVATE KEY-----";
	}
	to_pem() {
		return this.as_pem();
	}
	as_asn1() {
		const key = this.as_struct();
		return DstuPrivkey.encode(key, "der");
	}
	to_asn1() {
		return this.as_asn1();
	}
	as_struct() {
		return {
			version: 0,
			priv0: {
				id: "DSTU_4145_LE",
				p: {
					p: {
						type: "params",
						value: this.curve.as_struct()
					},
					sbox: DEFAULT_SBOX_COMPRESSED
				}
			},
			param_d: Array.prototype.slice.call(this.d.buf8()).reverse(),
			attr: []
		};
	}
	to_pbes2(password, algo) {
		const iv = rand_default(buffer.Buffer.alloc(8));
		const salt = rand_default(buffer.Buffer.alloc(32));
		return pbes2_serialize(algo.storesave(buffer.Buffer.from(this.to_asn1()), "PBES2", password, iv, salt));
	}
	static from_asn1(data, return_store) {
		return from_asn1(data, return_store);
	}
	static from_pem(data, return_store) {
		return from_asn1(maybe_pem(data), return_store);
	}
	static detect_format(inp) {
		return detect_format(inp);
	}
	static from_protected(data, password, algo) {
		let stores;
		if (password && (!algo || !algo.storeload)) throw new Error("Cant decode protected file without algo");
		data = maybe_pem(data);
		if (password) {
			stores = parseWithFn(data, [
				pbes2_parse,
				pfx_parse,
				enc_parse_many
			]);
			data = stores.map((part) => algo.storeload(part, password));
		} else data = [data];
		return merge_stores(data.map(guessStore));
	}
	static sign_serialise(data, fmt) {
		return sign_serialise(data, fmt);
	}
};
function merge_stores(list) {
	const ret = {
		certs: [],
		keys: [],
		format: "privkeys"
	};
	for (const store of list) {
		if (store.format === "privkeys") ret.keys = ret.keys.concat(store.keys);
		if (store.format === "certbags") ret.certs = ret.certs.concat(store.certs);
	}
	return ret;
}
function parseWithFn(data, parserFns) {
	for (let idx = 0; idx < parserFns.length; idx++) try {
		const ret = parserFns[idx](data);
		if (ret) return ret;
	} catch (e) {}
	throw new Error("Cant parse store with either PBES2 or proprietaty format");
}
function guessStore(data) {
	try {
		return Priv.from_asn1(data, true);
	} catch (e) {}
	return {
		format: "certbags",
		certs: certbags_from_asn1(data)
	};
}
//#endregion
//#region lib/standard.js
var standard_exports = /* @__PURE__ */ __exportAll({
	DSTU_PB_191: () => DSTU_PB_191,
	DSTU_PB_257: () => DSTU_PB_257,
	DSTU_PB_431: () => DSTU_PB_431,
	cache: () => cache
});
const DSTU_PB_257 = {
	a: "0",
	b: "01 CEF49472 0115657E 18F938D7 A7942394 FF9425C1 458C5786 1F9EEA6A DBE3BE10",
	base: {
		x: "2A29EF20 7D0E9B6C 55CD260B 306C7E00 7AC491CA 1B10C623 34A9E8DC D8D20FB7",
		y: "01 0686D41F F744D444 9FCCF6D8 EEA03102 E6812C93 A9D60B97 8B702CF1 56D814EF"
	},
	order: "80000000 00000000 00000000 00000000 6759213A F182E987 D3E17714 907D470D",
	kofactor: [4],
	m: 257,
	ks: [12]
};
const DSTU_PB_191 = {
	a: "1",
	b: "7bc86e2102902ec4d5890e8b6b4981ff27e0482750fefc03",
	base: {
		x: "714114b762f2ff4a7912a6d2ac58b9b5c2fcfe76daeb7129",
		y: "29c41e568b77c617efe5902f11db96fa9613cd8d03db08da"
	},
	order: "40000000000000000000000069a779cac1dabc6788f7474f",
	kofactor: [2],
	m: 191,
	ks: [9]
};
const DSTU_PB_431 = {
	a: "1",
	b: "03CE 10490F6A 708FC26D FE8C3D27 C4F94E69 0134D5BF F988D8D2 8AAEAEDE 975936C6 6BAC536B 18AE2DC3 12CA4931 17DAA469 C640CAF3",
	base: {
		x: "1A62 BA79D981 33A16BBA E7ED9A8E 03C32E08 24D57AEF 72F88986 874E5AAE 49C27BED 49A2A950 58068426 C2171E99 FD3B43C5 947C857D",
		y: "70B5 E1E14031 C1F70BBE FE96BDDE 66F45175 4B4CA5F4 8DA241F3 31AA396B 8D1839A8 55C1769B 1EA14BA5 3308B5E2 723724E0 90E02DB9"
	},
	order: "3FFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFBA3175 458009A8 C0A724F0 2F81AA8A 1FCBAF80 D90C7A95 110504CF",
	kofactor: [2],
	m: 431,
	ks: [
		1,
		3,
		5
	]
};
const cache = {};
//#endregion
//#region lib/point.js
var Point = class Point {
	constructor(curve, input_x, input_y) {
		let p_x;
		let p_y;
		if (input_y === void 0) {
			const coords = curve.expand(input_x);
			p_x = coords.x;
			p_y = coords.y;
		} else {
			p_x = input_x;
			p_y = input_y;
		}
		this.curve = curve;
		this.x = p_x._is_field ? p_x : new Field(p_x, "buf32", this.curve);
		this.y = p_y._is_field ? p_y : new Field(p_y, "buf32", this.curve);
		this._precomp = {
			pos: [this],
			neg: []
		};
	}
	add(point_1) {
		const a = this.curve.param_a;
		const point_2 = new Point(this.curve, this.curve.zero, this.curve.zero);
		const x0 = this.x;
		const y0 = this.y;
		const x1 = point_1.x;
		const y1 = point_1.y;
		if (this.is_zero()) return point_1;
		if (point_1.is_zero()) return this;
		let x2;
		let lbd;
		if (x0.equals(x1) === false) {
			const tmp = y0.add(y1);
			const tmp2 = x0.add(x1);
			lbd = tmp.mod_mul(tmp2.invert());
			x2 = a.add(lbd.mod_mul(lbd));
			x2.addM(lbd);
			x2.addM(x0);
			x2.addM(x1);
		} else {
			if (y1.equals(y0) === false) return point_2;
			if (x1.is_zero()) return point_2;
			lbd = x1.add(point_1.y.mod_mul(point_1.x.invert()));
			x2 = lbd.mod_mul(lbd).add(a);
			x2.addM(lbd);
		}
		const y2 = lbd.mod_mul(x1.add(x2));
		y2.addM(x2);
		y2.addM(y1);
		point_2.x = x2;
		point_2.y = y2;
		return point_2;
	}
	twice() {
		return this.add(this);
	}
	timesPow2(n) {
		let ret = this;
		let left = n;
		while (left) {
			ret = ret.twice();
			left -= 1;
		}
		return ret;
	}
	twicePlus(other) {
		return this.twice().add(other);
	}
	mul(param_n) {
		const point_s = new Point(this.curve, this.curve.zero, this.curve.zero);
		let point = this;
		let value_n = param_n;
		if (param_n.is_zero()) return point_s;
		if (value_n.is_negative()) {
			value_n = param_n.negate();
			point = this.negate();
		}
		return mulPos(point, param_n);
	}
	negate() {
		return new Point(this.curve, this.x, this.x.add(this.y));
	}
	is_zero() {
		return this.x.is_zero() && this.y.is_zero();
	}
	compress() {
		if (this.x.invert().mod_mul(this.y).trace() === 1) return this.x.setBit(0);
		return this.x.clearBit(0);
	}
	equals(other) {
		return other.x.equals(this.x) && other.y.equals(this.y);
	}
	toString() {
		return `<Point x:${this.x.toString(16)}, y:${this.y.toString(16)} >`;
	}
};
//#endregion
//#region lib/curve.js
const H = maybeHex;
const bn = asn1_js.default.bignum;
function fsquad_odd(value, curve) {
	const range_to = (curve.m - 1) / 2;
	const val_a = value.mod();
	let val_z = val_a;
	for (let idx = 1; idx <= range_to; idx += 1) {
		val_z = val_z.mod_sqr().mod_sqr();
		val_z.addM(val_a);
	}
	const val_w = val_z.mod_mul(val_z);
	val_w.addM(val_z);
	val_a.shiftRightM(1);
	val_w.shiftRightM(1);
	if (val_w.equals(val_a)) return val_z;
	throw new Error("squad eq fail");
}
function fsquad(value, curve) {
	let ret;
	if (curve.modulus.testBit(0)) ret = fsquad_odd(value, curve);
	else throw new Error("only odd modulus is supported :(");
	return ret.mod();
}
var Curve = class Curve {
	static resolve(def, fmt) {
		if (def.type === "params" && Curve.only_known) def = {
			type: "id",
			value: "DSTU_PB_" + def.value.p.param_m
		};
		if (def.type === "params") return Curve.from_asn1(def.value, fmt);
		if (def.type === "id") return Curve.from_id(def.value);
		throw new Error("Unknown type", def.type);
	}
	static from_id(curve_name) {
		if (cache[curve_name]) return cache[curve_name];
		if (!standard_exports[curve_name]) throw new Error("Curve with such name was not defined");
		const curve = new Curve(standard_exports[curve_name]);
		cache[curve_name] = curve;
		return curve;
	}
	static from_asn1(curve, fmt) {
		const big = fmt === "cert" ? BIG_LE : BIG_BE;
		return new Curve({
			m: curve.p.param_m,
			ks: Curve.ks_parse(curve.p.ks),
			a: [curve.param_a],
			b: big(curve.param_b),
			order: BIG_BE(curve.order.toArray()),
			kofactor: [2],
			base: big(curve.bp)
		});
	}
	static ks_parse(ks) {
		if (ks.type === "trinominal") return [ks.value];
		return [
			ks.value.k1,
			ks.value.k2,
			ks.value.k3
		];
	}
	constructor(params) {
		this.expand_cache = {};
		const mod_words = Math.ceil(params.m / 32);
		this.mod_tmp = new Uint32Array(mod_words + mod_words + 4);
		this.inv_tmp1 = new Uint32Array(mod_words);
		this.inv_tmp2 = new Uint32Array(mod_words);
		this.order = H(params.order, mod_words);
		this.kofactor = H(params.kofactor);
		this.param_a = H(params.a, mod_words);
		this.param_b = H(params.b, mod_words);
		this.m = typeof params.m === "number" ? params.m : params.m.toNumber();
		this.ks = params.ks;
		this.mod_words = mod_words;
		this.zero = new Field([0], "buf32", this);
		this.one = new Field("1", "hex", this);
		this.modulus = this.comp_modulus(params.m, params.ks);
		this.mod_bits = new Uint32Array([this.m].concat(this.ks, [0]));
		this.param_a = new Field(this.param_a, "buf32", this);
		this.param_b = new Field(this.param_b, "buf32", this);
		this.a = this.param_a;
		this.b = this.param_b;
		this.order = new Field(this.order, "buf32", this);
		this.kofactor = new Field(this.kofactor, "buf32", this);
		let base_x;
		let base_y;
		if (params.base.x === void 0) ({x: base_x, y: base_y} = this.expand(H(params.base, mod_words)));
		else {
			base_x = H(params.base.x, mod_words);
			base_y = H(params.base.y, mod_words);
		}
		this.set_base(base_x, base_y);
	}
	comp_modulus(m, ks) {
		let modulus = this.one;
		modulus = modulus.setBit(m);
		for (let i = 0; i < ks.length; i += 1) modulus = modulus.setBit(ks[i]);
		return modulus;
	}
	set_base(base_x, base_y) {
		let width = getWindowSize(this.m);
		width = Math.max(2, Math.min(16, width));
		this.base = this.point(base_x, base_y);
		precomp(this.base, width);
		const cmp = this.base.compress();
		this.expand_cache[cmp.toString()] = this.base;
	}
	expand(val) {
		const pa = this.a;
		const pb = this.b;
		let x;
		let y;
		if (typeof val === "string") x = new Field(val, "hex", this);
		else x = val;
		x = x._is_field ? x : new Field(x, "buf32", this);
		if (x.is_zero()) return {
			x,
			y: pb.mod_mul(pb)
		};
		const cached = this.expand_cache[x.toString()];
		if (cached !== void 0) return cached;
		const k = x.testBit(0);
		x = x.clearBit(0);
		const trace = x.trace();
		if (trace !== 0 && pa.is_zero() || trace === 0 && pa.equals(this.one)) x = x.setBit(0);
		const x2 = x.mod_mul(x);
		y = x2.mod_mul(x);
		if (pa.equals(this.one)) y.addM(x2);
		y.addM(pb);
		const invx2 = x2.invert();
		y = y.mod_mul(invx2);
		y = fsquad(y, this);
		const trace_y = y.trace();
		if (k === true && trace_y === 0 || k === false && trace_y !== 0) y.bytes[0] ^= 1;
		y = y.mod_mul(x);
		return {
			x,
			y
		};
	}
	field(val) {
		return new Field(val.bytes, void 0, this).mod();
	}
	point(px, py) {
		return new Point(this, px, py);
	}
	truncateTo(value, bits) {
		const big = new bn.BN(value.buf8(), 8);
		const mod = new bn.BN(1).shln(bits);
		return new Field(big.mod(mod).toArray(), "buf8", this);
	}
	truncate(value) {
		return this.truncateTo(value, this.m);
	}
	contains(point) {
		let lh = point.x.add(this.a);
		lh = lh.mod_mul(point.x);
		lh.addM(point.y);
		lh = lh.mod_mul(point.x);
		lh.addM(this.b);
		const y2 = point.y.mod_mul(point.y);
		lh.addM(y2);
		return lh.is_zero();
	}
	rand() {
		const bits = this.order.bitLength();
		const words = Math.ceil(bits / 8);
		let ret;
		do {
			let rand8 = new global.Uint8Array(words);
			rand8 = rand_default(rand8);
			ret = new Field(rand8, "buf8", this);
		} while (this.order.less(ret));
		return ret;
	}
	pkey(inp, fmt) {
		const format = fmt || Priv.detect_format(inp);
		return new Priv(this, new Field(inp, format, this));
	}
	pubkey(inp, input_fmt) {
		let fmt = input_fmt || Pub.detect_format(inp);
		if (fmt === "raw") fmt = "buf32";
		const compressed = new Field(inp, fmt, this);
		const pointQ = this.point(compressed);
		return new Pub(this, pointQ, inp);
	}
	equals(other) {
		const for_check = [
			"a",
			"b",
			"order",
			"modulus"
		];
		for (let i = 0; i < for_check.length; i += 1) {
			const attr = for_check[i];
			if (!this[attr].equals(other[attr])) return false;
		}
		return this.base.equals(other.base);
	}
	keygen() {
		let priv;
		let pub;
		do {
			const rand_d = this.rand();
			priv = new Priv(this, rand_d);
			pub = priv.pub();
		} while (!pub.validate());
		return priv;
	}
	as_struct() {
		let ks_p;
		if (this.ks.length === 1) ks_p = {
			type: "trinominal",
			value: this.ks[0]
		};
		else {
			ks_p = this.ks;
			ks_p = {
				type: "pentanominal",
				value: {
					k1: ks_p[0],
					k2: ks_p[1],
					k3: ks_p[2]
				}
			};
		}
		return {
			p: {
				param_m: this.m,
				ks: ks_p
			},
			param_a: this.param_a.bytes[0],
			param_b: this.param_b.le(),
			order: new bn.BN(this.order.buf8(), 8),
			bp: this.base.compress().le()
		};
	}
	calc_modulus() {
		const ret = new global.Uint32Array(this.mod_words);
		ret[0] = 1;
		let word = Math.floor(this.m / 32);
		let bit = this.m % 32;
		ret[word] |= 1 << bit;
		for (let i = 0; i < this.ks.length; i += 1) {
			word = Math.floor(this.ks[i] / 32);
			bit = this.ks[i] % 32;
			ret[word] |= 1 << bit;
		}
		return ret;
	}
	curve_id() {
		return {
			163: 0,
			167: 1,
			173: 2,
			179: 3,
			191: 4,
			233: 5,
			257: 6,
			307: 7,
			367: 8,
			431: 9
		}[this.m];
	}
	name() {
		return [
			"DSTU_PB_163",
			"DSTU_PB_167",
			"DSTU_PB_173",
			"DSTU_PB_179",
			"DSTU_PB_191",
			"DSTU_PB_233",
			"DSTU_PB_257",
			"DSTU_PB_307",
			"DSTU_PB_367",
			"DSTU_PB_431"
		][this.curve_id()];
	}
};
function pubkey(curve_name, key_data, key_fmt) {
	return Curve.from_id(curve_name).pubkey(key_data, key_fmt);
}
function pkey(curve_name, key_data, key_fmt) {
	return Curve.from_id(curve_name).pkey(key_data, key_fmt);
}
const std_curve = (id) => Curve.from_id(id);
//#endregion
//#region lib/util/str.js
function encodeUtf8Str(input, encoder) {
	return asn1_js.default.define("UTF8STR", function UTF8STR() {
		this.utf8str();
	}).encode(input, encoder);
}
//#endregion
//#region \0@oxc-project+runtime@0.139.0/helpers/esm/typeof.js
function _typeof(o) {
	"@babel/helpers - typeof";
	return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(o) {
		return typeof o;
	} : function(o) {
		return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o;
	}, _typeof(o);
}
//#endregion
//#region \0@oxc-project+runtime@0.139.0/helpers/esm/toPrimitive.js
function toPrimitive(t, r) {
	if ("object" != _typeof(t) || !t) return t;
	var e = t[Symbol.toPrimitive];
	if (void 0 !== e) {
		var i = e.call(t, r || "default");
		if ("object" != _typeof(i)) return i;
		throw new TypeError("@@toPrimitive must return a primitive value.");
	}
	return ("string" === r ? String : Number)(t);
}
//#endregion
//#region \0@oxc-project+runtime@0.139.0/helpers/esm/toPropertyKey.js
function toPropertyKey(t) {
	var i = toPrimitive(t, "string");
	return "symbol" == _typeof(i) ? i : i + "";
}
//#endregion
//#region \0@oxc-project+runtime@0.139.0/helpers/esm/defineProperty.js
function _defineProperty(e, r, t) {
	return (r = toPropertyKey(r)) in e ? Object.defineProperty(e, r, {
		value: t,
		enumerable: !0,
		configurable: !0,
		writable: !0
	}) : e[r] = t, e;
}
//#endregion
//#region lib/models/Certificate.js
const OID = {
	"1 2 804 2 1 1 1 11 1 4 1 1": "DRFO",
	"1 2 804 2 1 1 1 11 1 4 7 1": "DRFO",
	"1 2 804 2 1 1 1 11 1 4 2 1": "EDRPOU"
};
const OID_LINK = {
	"1 3 6 1 5 5 7 48 1": "ocsp",
	"1 3 6 1 5 5 7 48 2": "issuers",
	"1 3 6 1 5 5 7 48 3": "tsp"
};
const IPN_VAL = asn1_js.default.define("IPN_VAL", function body_IPN_VAL() {
	this.implicit(19).octstr();
});
const IPN_ID = asn1_js.default.define("IPN_ID", function body_IPN_ID() {
	this.seq().obj(this.key("id").objid(OID), this.key("val").setof(IPN_VAL));
});
const IPN = asn1_js.default.define("IPN", function body_IPN() {
	this.seqof(IPN_ID);
});
const UsageBits = asn1_js.default.define("USage", function body_Usage() {
	this.bitstr();
});
const Link = asn1_js.default.define("Link", function body_LINK() {
	this.seq().obj(this.key("id").objid(OID_LINK), this.key("link").implicit(6).ia5str());
});
const AIA = asn1_js.default.define("AIA", function body_AIA() {
	this.seqof(Link);
});
const KeyId = asn1_js.default.define("KeyId", function body_KeyId() {
	this.choice({
		str: this.octstr(),
		seq: this.seq().obj(this.key("str").implicit(0).octstr())
	});
});
const CertificateList$1 = asn1_js.default.define("CertificateValues", function() {
	this.seqof(Certificate$1);
});
function reprstr(buf) {
	let off = 2;
	if (buf[1] & 128) off += buf[1] ^ 128;
	if (buf[0] === 12) return buf.slice(off).toString("utf8");
	return buf.slice(off).toString("binary");
}
function str(input) {
	return asn1_js.default.define("STR", function STR() {
		this.octstr();
	}).encode(input, "der");
}
function parse_aia(data) {
	return AIA.decode(data, "der").reduce((acc, item) => {
		acc[item.id] = item.link;
		return acc;
	});
}
function parse_ipn(data) {
	const ret = {};
	const asn_ib = IPN.decode(data, "der");
	for (let i = 0; i < asn_ib.length; i += 1) {
		const part = asn_ib[i];
		ret[part.id] = String.fromCharCode.apply(null, part.val[0]);
	}
	return ret;
}
function optional(fn) {
	return function(data) {
		return data ? fn(data) : null;
	};
}
function parse_ext(asn_ob) {
	const ext = {};
	for (let part of asn_ob) ext[part.extnID] = part.extnValue;
	return {
		keyUsage: ext.keyUsage,
		extendedKeyUsage: ext.extendedKeyUsage,
		basicConstraints: ext.basicConstraints,
		ipn: optional(parse_ipn)(ext.subjectDirectoryAttributes),
		authorityInfoAccess: optional(parse_aia)(ext.authorityInfoAccess),
		subjectInfoAccess: optional(parse_aia)(ext.subjectInfoAccess),
		subjectKeyIdentifier: optional(parseKeyId)(ext.subjectKeyIdentifier),
		authorityKeyIdentifier: optional(parseKeyId)(ext.authorityKeyIdentifier)
	};
}
function parse_dn(asn_ob) {
	const ret = {};
	for (let i = 0; i < asn_ob.length; i += 1) for (let j = 0; j < asn_ob[i].length; j += 1) {
		const part = asn_ob[i][j];
		ret[part.type] = reprstr(part.value);
	}
	return ret;
}
function parseKeyId(buffer) {
	const ob = KeyId.decode(buffer, "der");
	return ob.type === "str" ? ob.value : ob.value.str;
}
function as_hex(buffer) {
	return buffer.toString("hex");
}
function makeRDN(obj) {
	return {
		type: "rdn",
		value: Object.entries(obj).map(([type, value]) => [{
			type,
			value: encodeUtf8Str(value, "der")
		}])
	};
}
var Certificate = class Certificate {
	static from_asn1(data) {
		const cert = Certificate$1.decode(data, "der");
		cert._raw = data;
		return new Certificate(cert);
	}
	static from_pem(data) {
		return Certificate.from_asn1(maybe_pem(data));
	}
	static encodeTBS(obj) {
		return TBSCertificate.encode(obj, "der");
	}
	static createTBS({ serial, pubkey, algorithm, sbox, curve, issuer, subject, valid, usage, hash }) {
		return {
			version: "v3",
			serialNumber: serial,
			issuer: makeRDN(issuer),
			subject: makeRDN(subject),
			subjectPublicKeyInfo: {
				subjectPublicKey: { data: pubkey.serialize() },
				algorithm: {
					algorithm,
					parameters: {
						curve: {
							type: "id",
							value: curve
						},
						dke: sbox
					}
				}
			},
			validity: {
				notBefore: {
					type: "utcTime",
					value: valid.from
				},
				notAfter: {
					type: "utcTime",
					value: valid.to
				}
			},
			extensions: [
				{
					extnID: "subjectKeyIdentifier",
					extnValue: str(pubkey.keyid({ hash }))
				},
				{
					extnID: "authorityKeyIdentifier",
					extnValue: str(pubkey.keyid({ hash }))
				},
				{
					extnID: "keyUsage",
					extnValue: Buffer.from(usage, "binary"),
					critical: true
				}
			],
			signature: { algorithm }
		};
	}
	static signCert({ privkey, hash, certData }) {
		const tbs = Certificate.createTBS(Object.assign({}, {
			algorithm: privkey.algorithm,
			curve: privkey.curve.name(),
			sbox: privkey.sbox,
			hash,
			pubkey: privkey.pub()
		}, certData));
		return new Certificate({
			tbsCertificate: tbs,
			signatureAlgorithm: { algorithm: privkey.algorithm },
			signature: {
				unused: 0,
				data: str(privkey.sign(hash(Certificate.encodeTBS(tbs)), "le"))
			}
		});
	}
	static formatDN(rdnlist) {
		const part = [];
		rdnlist.forEach((elements) => {
			elements.forEach((el) => {
				part.push(`${el.type}=${reprstr(el.value)}`);
			});
		});
		return part.join("/");
	}
	static formatRDN(serial, rdnlist) {
		return `${serial.toString(16)}@${Certificate.formatDN(rdnlist)}`;
	}
	constructor(cert, lazy) {
		this.setup(cert, lazy);
		this._raw = cert._raw;
		delete cert._raw;
	}
	setup(cert, lazy) {
		const tbs = cert.tbsCertificate;
		const pk = tbs.subjectPublicKeyInfo;
		const pk_data = pk.subjectPublicKey.data.slice(2);
		this.format = "x509";
		this.curve = pk.algorithm.algorithm === "Dstu4145le" ? Curve.resolve(pk.algorithm.parameters.curve, "cert") : null;
		this.curve_id = pk.algorithm.algorithm === "ECDSA" ? pk.algorithm.parameters.value : null;
		this.pk_data = BIG_LE(pk_data);
		this.valid = {
			from: tbs.validity.notBefore.value,
			to: tbs.validity.notAfter.value
		};
		this.serial = cert.tbsCertificate.serialNumber;
		this.signatureAlgorithm = cert.signatureAlgorithm.algorithm;
		this.pubkeyAlgorithm = cert.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
		this.extension = parse_ext(cert.tbsCertificate.extensions);
		this.issuer = parse_dn(cert.tbsCertificate.issuer.value);
		this.subject = parse_dn(cert.tbsCertificate.subject.value);
		this.ob = cert;
		if (!lazy && this.curve) this.pubkey_unpack();
	}
	verify({ time, usage }, hashes, lookupFn) {
		const issuer = lookupFn(this.issuerDN(), this.authorityKeyId);
		return issuer && (issuer.isRoot() ? issuer.trusted && issuer.verifySelfSigned({ time }, hashes) : issuer.verify({
			time: this.valid.from,
			usage: "ca"
		}, hashes, lookupFn)) && (usage ? this.canUseFor(usage) : true) && this.verifyTime(Number(time)) && this.verifySignature(issuer.pubkey_unpack(), hashes) && this.extension.authorityKeyIdentifier.equals(issuer.extension.subjectKeyIdentifier) && this.extension.subjectKeyIdentifier.equals(this.pubkey.keyid({ hash: hashes.Dstu4145le }));
	}
	verifySelfSigned({ time, usage }, hashes) {
		return usage ? this.canUseFor(usage) : this.verifyTime(time) && this.verifySignature(this.pubkey_unpack(), hashes) && this.pubkey.keyid({ hash: hashes.Dstu4145le }).equals(this.extension.subjectKeyIdentifier) && this.extension.authorityKeyIdentifier.equals(this.extension.subjectKeyIdentifier);
	}
	verifyTime(time) {
		return time >= this.valid.from && time < this.valid.to;
	}
	verifySignature(pubkey, hashFuncs) {
		const tbs = Certificate.encodeTBS(this.ob.tbsCertificate);
		const hashFn = hashFuncs[this.signatureAlgorithm];
		if (!hashFn) return false;
		const tbsHash = hashFn(tbs);
		return pubkey.verify(tbsHash, this.ob.signature.data);
	}
	getCompleteChain(lookupFn) {
		if (this.isRoot()) return [];
		const issuer = lookupFn(this.issuerDN(), this.authorityKeyId);
		return [issuer, ...issuer.getCompleteChain(lookupFn)];
	}
	pubkey_unpack() {
		if (!this.pubkey) this.pubkey = this.curve.pubkey(this.pk_data);
		return this.pubkey;
	}
	as_asn1() {
		if (this._raw !== void 0) return this._raw;
		return Certificate$1.encode(this.ob, "der");
	}
	to_asn1() {
		return this.as_asn1();
	}
	as_pem() {
		return `-----BEGIN CERTIFICATE-----\n${b64_encode(this.to_asn1(), {
			line: 16,
			pad: true
		})}\n-----END CERTIFICATE-----`;
	}
	to_pem() {
		return this.as_pem();
	}
	as_dict() {
		const x = this;
		return {
			subject: x.subject,
			issuer: x.issuer,
			extension: {
				ipn: x.extension.ipn,
				authorityInfoAccess: x.extension.authorityInfoAccess,
				subjectInfoAccess: x.extension.subjectInfoAccess,
				subjectKeyIdentifier: optional(as_hex)(x.extension.subjectKeyIdentifier),
				authorityKeyIdentifier: optional(as_hex)(x.extension.authorityKeyIdentifier)
			},
			usage: {
				sign: this.canUseFor("sign"),
				encrypt: this.canUseFor("encrypt")
			},
			valid: x.valid
		};
	}
	nameSerial() {
		return {
			issuer: this.ob.tbsCertificate.issuer,
			serialNumber: this.ob.tbsCertificate.serialNumber
		};
	}
	rdnSerial() {
		return Certificate.formatRDN(this.ob.tbsCertificate.serialNumber, this.ob.tbsCertificate.issuer.value);
	}
	isRoot() {
		return this.issuerDN() === this.subjectDN();
	}
	issuerDN() {
		return Certificate.formatDN(this.ob.tbsCertificate.issuer.value);
	}
	subjectDN() {
		return Certificate.formatDN(this.ob.tbsCertificate.subject.value);
	}
	name_asn1() {
		return Name.encode(this.ob.tbsCertificate.issuer, "der");
	}
	canUseFor(op) {
		const { keyUsage, extendedKeyUsage, basicConstraints } = this.extension;
		if (op === "ca") {
			if (!basicConstraints) return false;
			return BasicConstraints.decode(basicConstraints, "der").cA;
		}
		const usage = {
			sign: 128,
			encrypt: 8
		};
		if (usage.hasOwnProperty(op)) {
			const bits = UsageBits.decode(keyUsage, "der");
			const mask = usage[op];
			return (mask & bits.data[0]) === mask;
		}
		if (!extendedKeyUsage) return true;
		return ExtKeyUsageSyntax.decode(extendedKeyUsage, "der").includes(op);
	}
	get ocspLink() {
		const { id, link } = this.extension.authorityInfoAccess;
		return id === "ocsp" ? link : null;
	}
};
_defineProperty(Certificate, "List", { toCades(list) {
	return CertificateList$1.encode(list.map((iter) => iter.ob), "der");
} });
//#endregion
//#region lib/spec/rfc3161-tsp.js
var TimeStampReq = asn1_js.default.define("TimeStampReq", function() {
	this.seq().obj(this.key("version").int({ 1: "v1" }), this.key("messageImprint").use(MessageImprint));
});
var MessageImprint = asn1_js.default.define("MessageImprint", function() {
	this.seq().obj(this.key("hashAlgorithm").use(AlgorithmIdentifier), this.key("hashedMessage").octstr());
});
var TimeStampResp = asn1_js.default.define("TimeStampResp", function() {
	this.seq().obj(this.key("status").use(PKIStatusInfo$1), this.key("timeStampToken").use(ContentInfo$2));
});
var PKIStatusInfo$1 = asn1_js.default.define("PKIStatusInfo", function() {
	this.seq().obj(this.key("status").int({
		0: "granted",
		1: "grantedWithMods",
		2: "rejection",
		3: "waiting",
		4: "revocationWarning"
	}), this.key("statusString").any().optional(), this.key("failInfo").any().optional());
});
var TSTInfoStr = asn1_js.default.define("TSTInfoStr", function() {
	this.octstr();
});
var TSTInfo = asn1_js.default.define("TSTInfoSeq", function() {
	this.seq().obj(this.key("version").int({ 1: "v1" }), this.key("policy").objid(), this.key("messageImprint").use(MessageImprint), this.key("serialNumber").int(), this.key("genTime").gentime(), this.key("accuracy").seq().optional(), this.key("ordering").bool().optional().def(false), this.key("nonce").int().optional(), this.key("tsa").use("GeneralName").optional(), this.key("extensions").any().optional());
});
ContentInfo$2.contentModel.tstInfo = TSTInfoStr;
var rfc3161_tsp_default = {
	TimeStampReq,
	TimeStampResp,
	TSTInfo
};
//#endregion
//#region lib/spec/rfc4210-cmp.js
var AnotherName = asn1_js.default.define("OtherName", function() {
	this.seq().obj(this.key("type-id").objid(), this.key("value").any());
});
var IA5String = asn1_js.default.define("IA5String", function() {
	this.ia5str();
});
var ORAddress = asn1_js.default.define("ORAddress", function() {
	this.any();
});
var EDIPartyName = asn1_js.default.define("EDIPartyName", function() {
	this.seq().obj(this.key("nameAssigner").implicit(0).optional().octstr(), this.key("partyName").implicit(1).octstr());
});
var KeyIdentifier = asn1_js.default.define("KeyIdentifier", function() {
	this.octstr();
});
var PKIFreeText = asn1_js.default.define("PKIFreeText", function() {
	this.octstr();
});
var InfoTypeAndValue = asn1_js.default.define("InfoTypeAndValue", function() {
	this.seq().obj(this.key("infoType").objid(), this.key("infoValue").optional().any());
});
var GeneralName = asn1_js.default.define("GeneralName", function() {
	this.choice({
		otherName: this.explicit(0).use(AnotherName),
		rfc822Name: this.explicit(1).use(IA5String),
		dNSName: this.explicit(2).use(IA5String),
		x400Address: this.explicit(3).use(ORAddress),
		directoryName: this.explicit(4).use(Name),
		ediPartyName: this.explicit(5).use(EDIPartyName),
		uniformResourceIdentifier: this.explicit(6).use(IA5String),
		iPAddress: this.explicit(7).octstr(),
		registeredID: this.explicit(8).objid()
	});
});
var PKIHeader = asn1_js.default.define("PKIHeader", function() {
	this.seq().obj(this.key("pvno").int().def(2), this.key("sender").use(GeneralName), this.key("recipient").use(GeneralName), this.key("messageTime").optional().implicit(0).gentime(), this.key("protectionAlg").optional().implicit(1).use(AlgorithmIdentifier), this.key("senderKID").optional().implicit(2).use(KeyIdentifier), this.key("recipKID").optional().implicit(3).use(KeyIdentifier), this.key("transactionID").optional().implicit(4).octstr(), this.key("senderNonce").optional().implicit(5).octstr(), this.key("recipNonce").optional().implicit(6).octstr(), this.key("freeText").optional().implicit(7).use(PKIFreeText), this.key("generalInfo").optional().implicit(8).seqof(InfoTypeAndValue));
});
var OptionalValidity = asn1_js.default.define("OptionalValidity", function() {
	this.seq().obj(this.key("notBefore").implicit(0).optional().use(Time), this.key("notAfter").implicit(1).optional().use(Time));
});
var CertTemplate = asn1_js.default.define("CertTemplate", function() {
	this.seq().obj(this.key("version").optional().implicit(0).use(Version$1), this.key("serialNumber").optional().implicit(1).use(CertificateSerialNumber$1), this.key("signingAlg").optional().implicit(2).use(AlgorithmIdentifier), this.key("issuer").optional().implicit(3).use(Name), this.key("validity").optional().implicit(4).use(OptionalValidity), this.key("subject").optional().implicit(5).use(Name), this.key("publicKey").optional().implicit(6).use(SubjectPublicKeyInfo), this.key("issuerUID").optional().implicit(7).use(UniqueIdentifier), this.key("subjectUID").optional().implicit(8).use(UniqueIdentifier), this.key("extensions").optional().implicit(8).use(Extensions));
});
var ProofOfPossession = asn1_js.default.define("ProofOfPossession", function() {
	this.choice({ raVerified: this.implicit(0).null_() });
});
var CertRequest = asn1_js.default.define("CertRequest", function() {
	this.seq().obj(this.key("certReqId").int(), this.key("certTemplate").use(CertTemplate), this.key("controls").optional().any());
});
var CertReqMsg = asn1_js.default.define("CertReqMsg", function() {
	this.seq().obj(this.key("certReq").use(CertRequest), this.key("popo").optional().use(ProofOfPossession));
});
var CertReqMessages = asn1_js.default.define("CertReqMessages", function() {
	this.seqof(CertReqMsg);
});
var PKIStatus = asn1_js.default.define("PKIStatus", function() {
	this.int();
});
var PKIStatusInfo = asn1_js.default.define("PKIStatusInfo", function() {
	this.seq().obj(this.key("status").use(PKIStatus), this.key("statusString").use(PKIFreeText).optional(), this.key("failInfo").optional().any());
});
var CertResponse = asn1_js.default.define("CertResponse", function() {
	this.seq().obj(this.key("certReqId").integer(), this.key("status").use(PKIStatusInfo));
});
var CertRepMessage = asn1_js.default.define("CertReqMessage", function() {
	this.seq().obj(this.key("caPubs").implicit(0).seqof(Certificate$1).optional(), this.key("response").seqof(CertResponse));
});
var PKIBody = asn1_js.default.define("PKIBody", function() {
	this.choice({
		ir: this.implicit(0).optional().use(CertReqMessages),
		ip: this.implicit(1).optional().use(CertRepMessage)
	});
});
var CMPCertificate = asn1_js.default.define("CMPCertificate", function() {
	this.use(Certificate$1);
});
var PKIProtection = asn1_js.default.define("PKIProtection", function() {
	this.bitstr();
});
asn1_js.default.define("PKIMessage", function() {
	this.seq().obj(this.key("header").use(PKIHeader), this.key("body").use(PKIBody), this.key("protection").optional().implicit(0).use(PKIProtection), this.key("extraCerts").optional().implicit(1).seqof(CMPCertificate));
});
//#endregion
//#region lib/spec/rfc5035-certid.js
var GeneralNames = asn1_js.default.define("GeneralNames", function() {
	this.seqof(GeneralName);
});
var IssuerSerial = asn1_js.default.define("IssuerSerial", function() {
	this.seq().obj(this.key("issuer").use(GeneralNames), this.key("serialNumber").use(CertificateSerialNumber$1));
});
var ESSCertIDv2 = asn1_js.default.define("ESSCertIDv2", function() {
	this.seq().obj(this.key("hashAlgorithm").use(AlgorithmIdentifier), this.key("certHash").octstr(), this.key("issuerSerial").use(IssuerSerial));
});
var SigningCertificateV2 = asn1_js.default.define("SigningCertificateV2", function() {
	this.seq().obj(this.key("certs").seqof(ESSCertIDv2), this.key("policies").optional().any());
});
SigningCertificateV2.wrap = function(cert, hash) {
	var data = { certs: [{
		hashAlgorithm: { algorithm: "Gost34311" },
		certHash: hash,
		issuerSerial: {
			issuer: [{
				type: "directoryName",
				value: cert.tbsCertificate.issuer
			}],
			serialNumber: cert.tbsCertificate.serialNumber
		}
	}] };
	return SigningCertificateV2.encode(data, "der");
};
//#endregion
//#region lib/util/packed_xml.js
var Stream = {
	inStream: function(data) {
		this.offset = 0;
		this.data = data;
		this.readByte = function() {
			return this.data[this.offset++];
		};
		this.readUInt32LE = function() {
			var res = this.data.readUInt32LE(this.offset);
			this.offset += 4;
			return res;
		};
		return this;
	},
	outStream: function(size) {
		this.offset = 0;
		this.data = buffer.Buffer.alloc(size);
		this.writeByte = function(value) {
			this.data[this.offset++] = value;
		};
		return this;
	}
};
function getVersion(data, dataLen) {
	var bytes = [
		49,
		50,
		51,
		52,
		53,
		54,
		55,
		56,
		57,
		48
	];
	var res = {
		newFormat: false,
		nVer: -1,
		bRand: 0
	};
	if (dataLen < 77) return res;
	for (var count = 0; count < 10; count++) if ((data[dataLen - 13 + count] ^ data[dataLen - 23 + count]) !== bytes[count]) return res;
	res.newFormat = true;
	res.bRand = data[dataLen - 3];
	res.nVer = data[dataLen - 2] ^ data[dataLen - 25];
	return res;
}
function unobfuscate(packedXmlData) {
	var dataLen = packedXmlData.length, fileInfo;
	if (packedXmlData.slice(0, 10).toString() !== "PACKED_XML") throw Error("This is not PACKED_XML");
	packedXmlData.readUInt32LE(11);
	fileInfo = getVersion(packedXmlData.slice(15), dataLen - 15);
	if (fileInfo.newFormat) if (fileInfo.nVer === 1) {
		var count1 = dataLen - 28 > 1024 ? 512 : (dataLen - 28) / 2;
		for (var count = 0; count < count1; count++) packedXmlData[15 + count] ^= packedXmlData[15 + dataLen - 28 - count1 + count] ^ fileInfo.bRand;
	} else throw Error("Unsupported PACKED_XML version: " + fileInfo.nVer);
	else {
		dataLen - 15 > 160 ? count1 = 160 : count1 = dataLen - 15;
		for (var count = 0; count < count1; count++) packedXmlData[15 + count] ^= xorStr[count % 16];
	}
	return packedXmlData.slice(16);
}
function unlzma(lzmaData) {
	var decoder, outSize, inStream = new Stream.inStream(lzmaData), outStream;
	var decoder = new js_lzma.default.Decoder();
	if (!decoder.setDecoderProperties(inStream)) throw Error("Incorrect LZMA stream properties");
	outSize = inStream.readUInt32LE();
	outStream = new Stream.outStream(outSize);
	inStream.readUInt32LE();
	if (!decoder.decode(inStream, outStream, outSize)) throw Error("Error in LZMA data stream");
	return outStream.data;
}
function unpack$1(data) {
	var lzmaData = unobfuscate(data);
	if (lzmaData === void 0) throw Error("Error unobfuscating data");
	return unlzma(lzmaData);
}
//#endregion
//#region lib/util/invariant.js
function invariant(value, text) {
	if (!value) return new Error(text);
	return Boolean(invariant);
}
//#endregion
//#region lib/util/transport.js
const regexp = /* @__PURE__ */ new RegExp("<([\\w][\\w\\d]*)([^>]*)>([\\s\\S]*?)</\\1>", "g");
function U32(number) {
	const ret = buffer.Buffer.alloc(4);
	ret.writeUInt32LE(number);
	return ret;
}
function write_buf(buf, data) {
	invariant(data.length > 0, "Attempt to write empty buffer");
	invariant(buffer.Buffer.isBuffer(buf), "First argument should be buffer");
	invariant(buffer.Buffer.isBuffer(data) || typeof data === "string", "Second argument should be buffer or string");
	return buffer.Buffer.concat([buf, typeof data === "string" ? buffer.Buffer.from(data, "binary") : data]);
}
function transport_header(rb, headers) {
	rb = write_buf(rb, "TRANSPORTABLE\0");
	let h_buf = buffer.Buffer.alloc(0);
	Object.entries(headers).forEach(function([key, value]) {
		h_buf = write_buf(h_buf, key);
		h_buf = write_buf(h_buf, "=");
		h_buf = write_buf(h_buf, value);
		h_buf = write_buf(h_buf, "\r\n");
	});
	h_buf = write_buf(h_buf, "\0");
	rb = write_buf(rb, U32(h_buf.length));
	rb = write_buf(rb, h_buf);
	return rb;
}
function transport_encode(documents, headers) {
	let rb = buffer.Buffer.alloc(0);
	rb = headers ? transport_header(rb, headers) : rb;
	documents.forEach(function(el) {
		rb = write_buf(rb, el.type);
		rb = write_buf(rb, "\0");
		rb = write_buf(rb, U32(el.contents.length));
		rb = write_buf(rb, el.contents);
	});
	return rb;
}
var header_decode = function(buffer$1) {
	var ret = {};
	var key, val;
	var idx = 0;
	var st = idx;
	while (buffer$1[idx]) {
		if (buffer$1[idx] === 61) {
			key = buffer$1.slice(st, idx).toString();
			st = idx + 1;
		}
		if (buffer$1[idx] === 10 && buffer$1[idx - 1] === 13) {
			val = buffer$1.slice(st, idx - 1);
			ret[key] = val.toString("binary");
			st = idx + 1;
		}
		idx++;
	}
	return ret;
};
var qlb_split = function(buffer$2, print) {
	var off = 0;
	var ret = {
		data: [],
		hash: []
	};
	var clen;
	var prev;
	while (off < buffer$2.length) if (buffer$2[off] === 2) {
		off++;
		clen = buffer$2.readUInt32LE(off);
		off += 4;
		if (clen > 0) {
			ret.data.push(buffer$2.slice(off, off + clen));
			prev = "data";
		} else prev = "zero";
		off += clen;
	} else if (buffer$2[off] === 32) {
		off++;
		clen = 32;
		ret.hash.push(buffer$2.slice(off, off + clen));
		off += clen;
		prev = "hash";
	} else if (buffer$2.readUInt32BE(off) === 0) {
		off += 4;
		prev = "zero";
	} else if (prev !== void 0) {
		clen = buffer$2.readUInt32LE(off);
		off += 4;
		ret.data.push(buffer$2.slice(off, off + clen));
		off += clen;
		prev = "data";
	} else throw new Error("Unable to split QLB");
	return ret;
};
var decode_packed_xml_contents = function(xmlBuf) {
	var partName;
	var res = [];
	var rootElement, childElement;
	if (xmlBuf.slice(0, 5).toString() !== "<?xml") throw Error("This is not XML");
	rootElement = regexp.exec(xmlBuf.toString());
	if (rootElement === null) throw Error("Invalid XML data - cannot find root element");
	if (rootElement.length < 4) throw Error("Invalid XML data - cannot process root element");
	regexp.lastIndex = 0;
	while ((childElement = regexp.exec(rootElement[3])) !== null) {
		if (childElement.length < 4) continue;
		partName = childElement[1] + childElement[2];
		res.push({
			name: partName,
			content: b64_decode(childElement[3])
		});
	}
	return res;
};
var transport_decode = function(buffer$3) {
	var ret = { docs: [] };
	var off = 0;
	var section = 0;
	var label;
	var clen;
	var ct;
	while (off < buffer$3.length) {
		if (buffer$3.slice(0, 10).toString() === "PACKED_XML") {
			try {
				ct = unpack$1(buffer$3);
				ct = decode_packed_xml_contents(ct);
			} catch (e) {
				console.error(e.message);
				throw e;
			}
			ret.header = {};
			while (ct.length > 0) {
				var doc = ct.shift();
				if (doc.name === "DOCUMENT") ret.docs.push({
					type: doc.name,
					contents: doc.content,
					encoding: "PACKED_XML_DOCUMENT"
				});
				else ret.header[doc.name] = doc.content;
			}
			break;
		}
		while (buffer$3[off] && off - section < 20) off++;
		if (buffer$3[off] !== 0) throw new Error("No label found");
		label = buffer$3.slice(section, off).toString();
		if (label === "USC_SIGN" || label === "USC_CRYPT") {
			off++;
			section = off;
			continue;
		}
		clen = buffer$3[++off];
		clen |= buffer$3[++off] << 8;
		clen |= buffer$3[++off] << 16;
		clen |= buffer$3[++off] << 24;
		off++;
		if (clen < 0 || clen + off > buffer$3.length) throw new Error("Invalid length of '" + label + "' section:" + clen);
		if (label === "TRANSPORTABLE" || label === "ZPOSTTRANSPORTABLE") ret.header = header_decode(buffer$3.slice(off, off + clen));
		else if (label === "QLB_SIGN") {
			ct = qlb_split(buffer$3.slice(off, off + clen), off);
			ret.docs.push({
				type: label,
				contents: ct.data[0],
				hash: ct.hash[0]
			});
			ret.docs.push({
				type: "DATA",
				contents: ct.data[1]
			});
		} else if (label == "QLB_CRYPT") {
			ct = qlb_split(buffer$3.slice(off, off + clen), off);
			ret.docs.push({
				type: "CERTCRYPT",
				contents: ct.data[0]
			});
			ret.docs.push({
				type: label,
				contents: ct.data[1],
				hash: ct.hash[0]
			});
		} else ret.docs.push({
			type: label,
			contents: buffer$3.slice(off, off + clen)
		});
		off += clen;
		section = off;
	}
	return ret;
};
var transport_default = {
	encode: transport_encode,
	decode: transport_decode
};
//#endregion
//#region lib/util/tsp.js
const useContentTsp = (value) => ["all", "content"].includes(value);
const useSignatureTsp = (value) => ["all", "signature"].includes(value);
//#endregion
//#region lib/spec/rfc2560-ocsp.js
var OCSPRequest = asn1_js.default.define("OCSPRequest", function() {
	this.seq().obj(this.key("tbsRequest").use(TBSRequest), this.key("optionalSignature").optional().explicit(0).use(Signature));
});
var TBSRequest = asn1_js.default.define("TBSRequest", function() {
	this.seq().obj(this.key("version").explicit(0).use(Version).def("v1"), this.key("requestorName").explicit(1).optional().use(GeneralName), this.key("requestList").seqof(Request), this.key("requestExtensions").explicit(2).optional().use(Extensions));
});
var Signature = asn1_js.default.define("Signature", function() {
	this.seq().obj(this.key("signatureAlgorithm").use(AlgorithmIdentifier), this.key("signature").bitstr(), this.key("certs").explicit(0).optional().seqof(Certificate$1));
});
var Version = asn1_js.default.define("Version", function() {
	this.int({ 0: "v1" });
});
var CertificateSerialNumber = asn1_js.default.define("CertificateSerialNumber", function() {
	this.int();
});
var Request = asn1_js.default.define("Request", function() {
	this.seq().obj(this.key("reqCert").use(CertID), this.key("singleRequestExtensions").explicit(0).optional().use(Extensions));
});
var CertID = asn1_js.default.define("CertID", function() {
	this.seq().obj(this.key("hashAlgorithm").use(AlgorithmIdentifier), this.key("issuerNameHash").octstr(), this.key("issuerKeyHash").octstr(), this.key("serialNumber").use(CertificateSerialNumber));
});
var OCSPResponse = asn1_js.default.define("OCSPResponse", function() {
	this.seq().obj(this.key("responseStatus").use(OCSPResponseStatus), this.key("responseBytes").optional().explicit(0).use(ResponseBytes));
});
var OCSPResponseStatus = asn1_js.default.define("OCSPResponseStatus", function() {
	this.enum({
		0: "successful",
		1: "malformedRequest",
		2: "internalError",
		3: "tryLater",
		5: "sigRequired",
		6: "unauthorized"
	});
});
var ResponseBytes = asn1_js.default.define("ResponseBytes", function() {
	this.seq().obj(this.key("responseType").objid(), this.key("response").octstr());
});
var BasicOCSPResponse = asn1_js.default.define("BasicOCSPResponse", function() {
	this.seq().obj(this.key("tbsResponseData").use(ResponseData), this.key("signatureAlgorithm").use(AlgorithmIdentifier), this.key("signature").bitstr(), this.key("certs").optional().explicit(0).seqof(Certificate$1));
});
var ResponseData = asn1_js.default.define("ResponseData", function() {
	this.seq().obj(this.key("version").explicit(0).use(Version).def("v1"), this.key("responderID").use(ResponderID), this.key("producedAt").gentime(), this.key("responses").seqof(SingleResponse), this.key("responseExtensions").optional().explicit(1).use(Extensions));
});
var ResponderID = asn1_js.default.define("ResponderID", function() {
	this.choice({
		byName: this.explicit(1).use(Name),
		byKey: this.explicit(2).use(KeyHash)
	});
});
var KeyHash = asn1_js.default.define("KeyHash", function() {
	this.octstr();
});
var SingleResponse = asn1_js.default.define("SingleResponse", function() {
	this.seq().obj(this.key("certID").use(CertID), this.key("certStatus").use(CertStatus), this.key("thisUpdate").gentime(), this.key("nextUpdate").optional().explicit(0).gentime(), this.key("singleExtensions").optional().explicit(1).use(Extensions));
});
var CertStatus = asn1_js.default.define("CertStatus", function() {
	this.choice({
		good: this.implicit(0).null_(),
		revoked: this.implicit(1).use(RevokedInfo),
		unknown: this.implicit(2).use(UnknownInfo)
	});
});
var RevokedInfo = asn1_js.default.define("RevokedInfo", function() {
	this.seq().obj(this.key("revocationTime").gentime(), this.key("revocationReason").optional().explicit(0).use(CRLReason));
});
var UnknownInfo = asn1_js.default.define("UnknownInfo", function() {
	this.null_();
});
//#endregion
//#region lib/spec/rfc5126-cades.js
const CertificateList = asn1_js.default.define("CertificateList", function() {
	this.any();
});
const CrlValidatedID = asn1_js.default.define("CrlValidatedID", function() {
	this.any();
});
const RevocationValues = asn1_js.default.define("RevocationValues", function() {
	this.seq().obj(this.key("crlVals").optional().explicit(0).seqof(CertificateList), this.key("ocspVals").optional().explicit(1).seqof(BasicOCSPResponse));
});
const OcspIdentifier = asn1_js.default.define("OcspIdentifier", function() {
	this.seq().obj(this.key("ocspResponderID").use(ResponderID), this.key("producedAt").gentime());
});
const OtherHashAlgAndValue = asn1_js.default.define("OtherHashAlgAndValue", function() {
	this.seq().obj(this.key("hashAlgorithm").use(AlgorithmIdentifier), this.key("hashValue").octstr());
});
const OcspResponsesID = asn1_js.default.define("OcspResponsesID", function() {
	this.seq().obj(this.key("ocspIdentifier").use(OcspIdentifier), this.key("ocspRepHash").optional().use(OtherHashAlgAndValue));
});
const OcspListID = asn1_js.default.define("OcspListID", function() {
	this.seq().obj(this.key("ocspResponses").seqof(OcspResponsesID));
});
const CrlOcspRef = asn1_js.default.define("CrlOcspRef", function() {
	this.seq().obj(this.key("crlids").optional().explicit(0).use(CrlValidatedID), this.key("ocspids").optional().explicit(1).use(OcspListID));
});
const RevocationRefs = asn1_js.default.define("CompleteRevocationRefs", function() {
	this.seqof(CrlOcspRef);
});
const OtherCertID = asn1_js.default.define("OtherCertID", function() {
	this.seq().obj(this.key("otherCertHash").use(OtherHashAlgAndValue), this.key("issuerSerial").optional().use(IssuerAndSerialNumber));
});
const CompleteCertificateRefs = asn1_js.default.define("CompleteCertificateRefs", function() {
	this.seqof(OtherCertID);
});
//#endregion
//#region lib/models/OcspResponse.js
var OCSPError = class extends Error {};
function encodeSpec(cert, serial, hashFn) {
	return certSpec = {
		hashAlgorithm: { algorithm: hashFn.algo || "Gost34311" },
		issuerNameHash: hashFn(cert.name_asn1()),
		issuerKeyHash: cert.extension.authorityKeyIdentifier,
		serialNumber: serial
	};
}
function findByName(query, list) {
	const rdn = Certificate.formatDN(query.value);
	for (let cert of list) if (Certificate.formatDN(cert.tbsCertificate.subject.value) === rdn) return new Certificate(cert);
	throw new OCSPError();
}
function findByKey(query, list) {
	for (let cert of list) {
		const keyIdExt = cert.tbsCertificate.extensions.find((e) => e.extnID === "subjectKeyIdentifier");
		if (!keyIdExt) continue;
		if (keyIdExt.extnValue.slice(2).equals(query)) return new Certificate(cert);
	}
	throw new OCSPError();
}
function checkNonce(tbs, nonce) {
	const ext = tbs.responseExtensions.find((part) => part.extnID === "OCSPNonce");
	if (!ext || !ext.extnValue.equals(nonce)) throw new OCSPError();
}
function findByIssuerSerial(list, issuerDN, serial) {
	return list.find((iter) => Certificate.formatDN(iter.tbsCertificate.issuer.value) === issuerDN && iter.tbsCertificate.serialNumber.eq(serial));
}
var Ref = class {
	constructor(ob) {
		this.ob = ob;
	}
};
Ref.toCades = function(list) {
	const ob = list.map((iter) => iter.length ? { ocspids: { ocspResponses: iter.map((ref) => ref.ob) } } : {});
	return RevocationRefs.encode(ob, "der");
};
Ref.fromCades = function(raw) {
	return RevocationRefs.decode(raw, "der").map((ob) => (ob.ocspids && ob.ocspids.ocspResponses || []).map((iter) => new Ref(iter)));
};
var OcspResponse = class OcspResponse {
	constructor(basic) {
		this.ob = basic;
	}
	makeRef(ctx) {
		return new Ref({
			ocspIdentifier: {
				ocspResponderID: this.ob.tbsResponseData.responderID,
				producedAt: this.ob.tbsResponseData.producedAt
			},
			ocspRepHash: {
				hashAlgorithm: { algorithm: ctx.hashFn.algo || "Gost34311" },
				hashValue: ctx.hashFn(this.to_asn1())
			}
		});
	}
	matches(cert, serial, ctx) {
		const [status] = this.ob.tbsResponseData.responses;
		const spec = OcspResponse.encodeSpec(cert, serial, ctx.hashFn);
		const specData = CertID.encode(spec);
		const respSpecData = CertID.encode(status.certID);
		return specData.equals(respSpecData);
	}
	verify(ctx, cert, serial, nonce, isOcspStamp) {
		const response = this.ob;
		const [status] = response.tbsResponseData.responses;
		const responderID = response.tbsResponseData.responderID;
		const queryFn = {
			byName: (query) => findByName(query, response.certs),
			byKey: (query) => findByKey(query, response.certs)
		}[responderID.type];
		if (!queryFn) throw new OCSPError();
		const responder = queryFn(responderID.value);
		if (!responder.verify({
			time: status.thisUpdate,
			usage: "ocspSigning"
		}, { Dstu4145le: ctx.hashFn }, ctx.lookupCA)) throw new OCSPError();
		if (!responder.extension.authorityKeyIdentifier.equals(cert.extension.authorityKeyIdentifier)) throw new OCSPError();
		const tbs = ResponseData.encode(response.tbsResponseData, "der");
		if (!responder.pubkey_unpack().verify(ctx.hashFn(tbs), response.signature.data)) throw new OCSPError();
		if (!isOcspStamp) checkNonce(response.tbsResponseData, nonce);
		const spec = OcspResponse.encodeSpec(cert, serial, ctx.hashFn);
		const specData = CertID.encode(spec);
		const respSpecData = CertID.encode(status.certID);
		if (!specData.equals(respSpecData)) throw new OCSPError();
		return {
			requestOk: true,
			statusOk: status.certStatus.type === "good",
			time: status.thisUpdate,
			isOcspStamp,
			cert: findByIssuerSerial(response.certs, cert.issuerDN(), serial)
		};
	}
	to_asn1() {
		return BasicOCSPResponse.encode(this.ob, "der");
	}
};
OcspResponse.fromBasic = function(raw) {
	return new OcspResponse(BasicOCSPResponse.decode(raw, "der"));
};
OcspResponse.fromCades = function(raw) {
	return RevocationValues.decode(raw, "der").ocspVals.map((ob) => new OcspResponse(ob));
};
OcspResponse.toCades = function(list) {
	const ocspVals = list.map((iter) => iter.ob);
	return RevocationValues.encode({ ocspVals }, "der");
};
OcspResponse.encodeSpec = encodeSpec;
OcspResponse.Ref = Ref;
//#endregion
//#region lib/models/CertificateRef.js
var CertificateRef = class CertificateRef {
	constructor(ob) {
		this.ob = ob;
	}
	static fromCert(cert, hashFn) {
		return new CertificateRef({
			otherCertHash: {
				hashAlgorithm: { algorithm: hashFn.algo || "Gost34311" },
				hashValue: hashFn(cert.to_asn1())
			},
			issuerSerial: cert.nameSerial()
		});
	}
	static toCades(list) {
		return CompleteCertificateRefs.encode(list.map((iter) => iter.ob), "der");
	}
};
//#endregion
//#region lib/models/Message.js
const { ContentInfo } = dstszi2010_exports;
function cmp(buf1, buf2) {
	let xor = 0;
	let idx = 0;
	for (idx = 0; idx < buf1.length && idx < buf2.length; idx += 1) xor |= buf1[idx] ^ buf2[idx];
	return xor === 0;
}
var Attrs = class {
	constructor(list) {
		this.list = list;
	}
	get index() {
		const ret = {};
		if (!this.list) return ret;
		for (let attr of this.list) if (typeof attr.type === "string") ret[attr.type] = attr.values[0];
		return Object.freeze(ret);
	}
	setAttr(type, value) {
		for (let attr of this.list) if (attr.type === type) return attr.values.push(value);
		this.list.push({
			type,
			values: [value]
		});
	}
};
var SignedAttrs = class extends Attrs {
	get messageDigest() {
		const messageDigest = this.index.messageDigest;
		if (!messageDigest || messageDigest[0] !== 4 || messageDigest[1] !== messageDigest.length - 2) return null;
		return messageDigest.slice(2);
	}
	set messageDigest(value) {
		this.setAttr("messageDigest", Data.encode(value, "der"));
	}
	get signingTime() {
		const stime = this.index.signingTime;
		return stime && Time.decode(stime, "der").value || null;
	}
	set signingTime(value) {
		const raw = Time.encode({
			type: "utcTime",
			value
		}, "der");
		this.setAttr("signingTime", raw);
	}
	get contentTimeStamp() {
		const raw = this.index.contentTimeStamp;
		return raw && new Message(raw) || null;
	}
	set contentTimeStamp(value) {
		this.setAttr("contentTimeStamp", value);
	}
	set signingCertificateV2(value) {
		this.setAttr("signingCertificateV2", SigningCertificateV2.wrap(value.cert.ob, value.hash));
	}
	set contentType(value) {
		const raw = ContentType.encode(value, "der");
		this.setAttr("contentType", raw);
	}
};
var UnsignedAttrs = class extends Attrs {
	get timeStampToken() {
		const raw = this.index.timeStampToken;
		return raw && new Message(raw) || null;
	}
	set timeStampToken(value) {
		this.setAttr("timeStampToken", value);
	}
	get revocationValues() {
		const raw = this.index.revocationValues;
		return raw && OcspResponse.fromCades(raw) || [];
	}
	set revocationValues(value) {
		this.setAttr("revocationValues", OcspResponse.toCades(value));
	}
	get revocationRefs() {
		const raw = this.index.revocationRefs;
		return raw && OcspResponse.Ref.fromCades(raw) || [];
	}
	set revocationRefs(value) {
		this.setAttr("revocationRefs", OcspResponse.Ref.toCades(value));
	}
	set certificateRefs(value) {
		this.setAttr("certificateRefs", CertificateRef.toCades(value));
	}
	set certificateValues(value) {
		this.setAttr("certificateValues", Certificate.List.toCades(value));
	}
};
var Message = class Message {
	constructor(asn1Ob) {
		if (buffer.Buffer.isBuffer(asn1Ob)) this.parse(asn1Ob);
		else if (typeof asn1Ob === "object") this.constructMessage(asn1Ob);
	}
	constructMessage(ob) {
		if (ob.type === "signedData") this.constructSigned(ob);
		if (ob.type === "envelopedData") this.constructEnveloped(ob);
		if (ob.type === "data") this.constructData(ob);
		this.cert = ob.cert;
	}
	constructData(ob) {
		const wrap = {
			contentType: ob.type,
			content: ob.data
		};
		this.wrap = wrap;
	}
	constructEnveloped(ob) {
		const { cert } = ob;
		const { dke } = cert.ob.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters;
		const enc = ob.crypter.encrypt(ob.data, ob.toCert, ob.algo);
		const kari = {
			version: 3,
			originator: {
				type: "issuerAndSerialNumber",
				value: cert.nameSerial()
			},
			ukm: enc.ukm,
			keyEncryptionAlgorithm: {
				algorithm: "dhSinglePass-cofactorDH-gost34311kdf",
				parameters: {
					algorithm: "Gost28147-cfb-wrap",
					parameters: null
				}
			},
			recipientEncryptedKeys: [{
				rid: {
					type: "issuerAndSerialNumber",
					value: ob.toCert.nameSerial()
				},
				encryptedKey: enc.wcek
			}]
		};
		const wrap = {
			contentType: ob.type,
			content: {
				version: 2,
				recipientInfos: [{
					type: "kari",
					value: kari
				}],
				encryptedContentInfo: {
					contentType: "data",
					encryptedContent: enc.data,
					contentEncryptionAlgorithm: {
						algorithm: "Gost28147-cfb",
						parameters: {
							type: "params",
							value: {
								iv: enc.iv,
								dke
							}
						}
					}
				}
			}
		};
		this.wrap = wrap;
	}
	constructSigned(ob) {
		const digestB = ob.dataHash || ob.data && ob.hash(ob.data);
		let { signB } = ob;
		const { tspB, tspTokenB } = ob;
		const wrap = {
			contentType: ob.type,
			content: {
				version: 1,
				digestAlgorithms: [{ algorithm: "Gost34311" }],
				contentInfo: ob.data ? {
					contentType: "data",
					content: ob.data
				} : { contentType: "data" },
				certificate: [ob.cert.ob],
				signerInfos: [{
					version: 1,
					sid: {
						type: "issuerAndSerialNumber",
						value: ob.cert.nameSerial()
					},
					digestAlgorithm: { algorithm: "Gost34311" },
					digestEncryptionAlgorithm: { algorithm: "Dstu4145le" },
					encryptedDigest: signB
				}]
			}
		};
		this.wrap = wrap;
		this.attrs = [];
		this.uattrs = [];
		this.parseAttrs();
		this.pattrs.signingCertificateV2 = {
			cert: ob.cert,
			hash: ob.hash(ob.cert.as_asn1())
		};
		this.pattrs.contentType = "data";
		this.pattrs.messageDigest = digestB;
		if (tspB) this.pattrs.contentTimeStamp = tspB;
		this.pattrs.signingTime = ob.signTime === void 0 ? new Date(Date.now()) : /* @__PURE__ */ new Date(1e3 * ob.signTime);
		this.saveAttrs();
		if (!signB) this.addSignature(ob.hash, ob.signer);
		this.addSignatureToken(tspTokenB);
	}
	addSignature(hash_f, signer) {
		this.signature = signer.sign(this.mhash(hash_f), "le");
		this.saveAttrs();
	}
	addSignatureToken(tspTokenB) {
		if (!tspTokenB) return;
		this.puattrs.timeStampToken = tspTokenB;
		this.saveAttrs();
	}
	addOcspResponses(list) {
		if (!list.length) return;
		this.puattrs.revocationValues = list;
		this.saveAttrs();
	}
	addOcspHashes(list) {
		if (!list.length) return;
		this.puattrs.revocationRefs = list;
		this.saveAttrs();
	}
	addCertRefs(list) {
		if (!list.length) return;
		this.puattrs.certificateRefs = list;
		this.saveAttrs();
	}
	addCertValues(list) {
		if (!list.length) return;
		this.puattrs.certificateValues = list;
		this.saveAttrs();
	}
	get type() {
		return this.wrap.contentType;
	}
	get info() {
		return this.wrap.content;
	}
	parse(data) {
		this.wrap = ContentInfo.decode(data, "der");
		if (this.type === "envelopedData") {
			this.enc_info = this.info.encryptedContentInfo;
			this.enc_params = this.enc_info.contentEncryptionAlgorithm.parameters.value;
			if (this.info.recipientInfos.length === 1) this.rki = this.info.recipientInfos[0].value;
			this.enc_contents = this.info.encryptedContentInfo.encryptedContent;
		}
		if (this.type === "signedData" && this.info.signerInfos.length) {
			this.attrs = this.info.signerInfos[0].authenticatedAttributes;
			this.uattrs = this.info.signerInfos[0].unauthenticatedAttributes;
		}
		this.parseAttrs();
	}
	mhash(hash_f) {
		let dataToSign;
		if (this.attrs) dataToSign = Attributes.encode(this.attrs, "der");
		else dataToSign = this.info.contentInfo.content;
		return hash_f(dataToSign);
	}
	parseAttrs() {
		this.pattrs = new SignedAttrs(this.attrs);
		this.puattrs = new UnsignedAttrs(this.uattrs);
	}
	saveAttrs() {
		this.info.signerInfos[0].authenticatedAttributes = this.pattrs.list;
		if (this.puattrs.list.length) this.info.signerInfos[0].unauthenticatedAttributes = this.puattrs.list;
	}
	verifyAttrs(hash_f, lookupCert, lookupCA, opts = {}) {
		if (!this.attrs) return true;
		let ok;
		ok = this.verifyAttrDigest(this.pattrs.messageDigest, hash_f);
		ok = ok && this.verifySigningTime(this.pattrs.signingTime, lookupCert);
		if (useContentTsp(opts.tsp)) ok = ok && this.verifyTimestampToken(this.pattrs.contentTimeStamp, hash_f, lookupCert, lookupCA, "content");
		if (useSignatureTsp(opts.tsp)) ok = ok && this.verifyTimestampToken(this.puattrs.timeStampToken, hash_f, lookupCert, lookupCA, "signature");
		return ok;
	}
	verifyAttrDigest(dgst, hash_f) {
		if (!dgst) return false;
		const dataToSign = this.info.contentInfo.content;
		return cmp(dgst, hash_f(dataToSign));
	}
	verifySigningTime(time, lookupCert) {
		if (!time) return true;
		const x509 = this.signer(lookupCert);
		return time >= x509.valid.from && time <= x509.valid.to;
	}
	verifyTimestampToken(msg, hash_f, lookupCert, lookupCA, imprintOf) {
		if (!msg) return true;
		if (!msg.verify(hash_f, lookupCert, lookupCA)) return false;
		const token = rfc3161_tsp_default.TSTInfo.decode(msg.content, "der");
		if (!msg.signer(lookupCert).verify({
			time: token.genTime,
			usage: "timeStamping"
		}, { Dstu4145le: hash_f }, lookupCA)) return false;
		if (token.messageImprint.hashAlgorithm.algorithm !== "Gost34311") return false;
		return cmp(token.messageImprint.hashedMessage, hash_f(this[imprintOf]));
	}
	get signature() {
		return this.info.signerInfos[0].encryptedDigest;
	}
	set signature(value) {
		this.info.signerInfos[0].encryptedDigest = value;
	}
	get content() {
		return this.info.contentInfo.content;
	}
	get signedWithCerts() {
		const tokens = [this.pattrs.contentTimeStamp, this.puattrs.timeStampToken].filter((msg) => msg).map((msg) => msg.signedWithCerts);
		return [this.signerRDN].concat(...tokens);
	}
	get signerRDN() {
		const [{ sid: { type, value } }] = this.info.signerInfos;
		if (type === "issuerAndSerialNumber") return value;
		if (type === "subjectKeyIdentifier") return { keyid: value };
		return null;
	}
	signer(lookupCert) {
		const [certificate] = this.info.certificate || [];
		if (certificate) return new Certificate(certificate);
		const query = this.signerRDN;
		const pubkey = query && lookupCert(query);
		if (pubkey) return pubkey;
		throw new Message.ENOCERT();
	}
	get tokenTime() {
		const msg = this.puattrs.timeStampToken;
		if (!msg) return null;
		return rfc3161_tsp_default.TSTInfo.decode(msg.info.contentInfo.content, "der").genTime;
	}
	get contentTime() {
		const msg = this.pattrs.contentTimeStamp;
		if (!msg) return null;
		return rfc3161_tsp_default.TSTInfo.decode(msg.info.contentInfo.content, "der").genTime;
	}
	get receiverKey() {
		const ri = this.info.recipientInfos[0];
		if (ri.type !== "kari") throw new Message.ENOCERT();
		return ri.value.recipientEncryptedKeys[0].rid;
	}
	verify(hash_f, lookupCert, lookupCA, opts = {}) {
		const hash = this.mhash(hash_f);
		if (!this.verifyAttrs(hash_f, lookupCert, lookupCA, opts)) return false;
		return this.signer(lookupCert).pubkey.verify(hash, this.signature, "le");
	}
	decrypt(crypter, algo, lookupCert) {
		let pubkey;
		const ri = this.info.recipientInfos[0];
		if (ri.type !== "kari") throw new Message.ENOCERT();
		if (ri.value.originator.type === "issuerAndSerialNumber") {
			pubkey = lookupCert(ri.value.originator.value);
			if (!pubkey) throw new Message.ENOCERT();
			pubkey = pubkey.pubkey;
		}
		if (ri.value.originator.type === "originatorKey") {
			const { originator } = this.info.recipientInfos[0].value;
			pubkey = originator.value.publicKey.data.slice(2);
			pubkey = crypter.curve.pubkey(add_zero(pubkey, true), "buf8");
		}
		const enc = this.info.encryptedContentInfo;
		const enc_param = enc.contentEncryptionAlgorithm.parameters.value;
		const rp = this.info.recipientInfos[0].value.recipientEncryptedKeys[0];
		const p = {
			ukm: this.info.recipientInfos[0].value.ukm,
			iv: enc_param.iv,
			wcek: rp.encryptedKey
		};
		return crypter.decrypt(enc.encryptedContent, pubkey, p, algo);
	}
	as_asn1() {
		return ContentInfo.encode(this.wrap, "der");
	}
	as_transport(opts, addCert) {
		const docs = [];
		let magic;
		if (this.type === "signedData") magic = "UA1_SIGN";
		if (this.type === "envelopedData") magic = "UA1_CRYPT";
		if (addCert) docs.push({
			type: "CERTCRYPT",
			contents: this.cert.as_asn1()
		});
		docs.push({
			type: magic,
			contents: this.as_asn1()
		});
		return transport_default.encode(docs, opts);
	}
};
_defineProperty(Message, "ENOCERT", class ENOCERT extends Error {
	constructor(..._args) {
		super(..._args);
		_defineProperty(this, "code", "ENOCERT");
	}
});
//#endregion
//#region lib/models/index.js
var models_exports = /* @__PURE__ */ __exportAll({
	Certificate: () => Certificate,
	Message: () => Message,
	Priv: () => Priv,
	Pub: () => Pub
});
//#endregion
//#region lib/app/keycoder.js
var Keycoder = class {
	constructor() {
		console.warn("Keycoder instances are deprecated. Use jk.guess_parse() to parse keys");
	}
	is_valid(indata) {
		return indata[0] === 48 && (indata[1] & 128) === 128;
	}
	is_pem(indata) {
		return is_pem(indata);
	}
	maybe_pem(indata) {
		return maybe_pem(indata);
	}
	parse(indata) {
		return guess_parse(indata);
	}
};
function privkey_parse(data) {
	return Priv.from_asn1(data, true);
}
function cert_parse(data) {
	return Certificate.from_asn1(data);
}
const parsers = [
	enc_parse,
	pbes2_parse,
	pfx_parse,
	privkey_parse,
	cert_parse
];
function guess_parse(indata) {
	if (!buffer.Buffer.isBuffer(indata)) indata = buffer.Buffer.from(indata, "binary");
	indata = maybe_pem(indata);
	for (const parser of parsers) try {
		return parser(indata);
	} catch (ignore) {}
	throw new Error("Unknown format");
}
//#endregion
//#region lib/util/complain.js
var EOLD = class extends Error {};
//#endregion
//#region lib/util/load.js
function loadJks(ret, store, password) {
	if (!password) throw new Error("JKS file format requires password to be opened");
	for (let part of store.material) {
		const buf = jksreader.default.decode(part.key, password.toString());
		if (!buf) throw new Error("Cant load key from store, check password");
		const rawStore = Priv.from_asn1(buf, true);
		for (let cert of part.certs) ret.push({ cert: Certificate.from_pem(cert) });
		for (let priv of rawStore.keys) ret.push({ priv });
	}
	return ret;
}
function load(keyinfo, algo) {
	let ret = [];
	if (keyinfo.priv && keyinfo.priv.type === "Priv") ret.push({ priv: keyinfo.priv });
	if (keyinfo.cert && keyinfo.cert.format === "x509") ret.push({ cert: keyinfo.cert });
	if (keyinfo.privPem) ret.push({ priv: Priv.from_pem(keyinfo.privPem) });
	if (keyinfo.certPem) ret.push({ cert: Certificate.from_pem(keyinfo.certPem) });
	let keyBuffers = keyinfo.keyBuffers || [];
	if (keyinfo.privPath) {
		let keyPaths = typeof keyinfo.privPath === "string" ? [keyinfo.privPath] : keyinfo.privPath || [];
		keyBuffers = [...keyBuffers, ...keyPaths.map((path) => fs.default.readFileSync(path))];
	}
	let certBuffers = keyinfo.certBuffers || [];
	if (keyinfo.certPath) {
		let certPaths = typeof keyinfo.certPath === "string" ? [keyinfo.certPath] : keyinfo.certPath || [];
		certBuffers = [...certBuffers, ...certPaths.map((path) => fs.default.readFileSync(path))];
	}
	keyBuffers.forEach((buf) => {
		const content = buf[0] === 81 ? buf.slice(6) : buf;
		const jksStore = jksreader.default.parse(content);
		if (jksStore) return loadJks(ret, jksStore, keyinfo.password);
		let store;
		try {
			store = Priv.from_protected(content, keyinfo.password, algo);
		} catch (ignore) {
			throw new Error("Cant load key from store");
		}
		store.keys.forEach((priv) => ret.push({ priv }));
		store.certs.forEach((cert) => ret.push({ cert: Certificate.from_asn1(cert) }));
	});
	certBuffers.forEach((cert) => ret.push({ cert: Certificate.from_pem(cert) }));
	return ret;
}
//#endregion
//#region lib/services/tsp.js
function getStampCb(cert, hashedMessage, query, cb, errorCb) {
	var tsp = rfc3161_tsp_default.TimeStampReq.encode({
		version: 1,
		messageImprint: {
			hashAlgorithm: { algorithm: "Gost34311" },
			hashedMessage
		}
	}, "der");
	return query("POST", cert.extension.subjectInfoAccess.link, {
		"Content-Type": "application/tsp-request",
		"Content-Length": tsp.length
	}, tsp, function(full) {
		if (!full) return errorCb(null);
		var rtsp = rfc3161_tsp_default.TimeStampResp.decode(full, "der");
		if (rtsp.status.status !== "granted") return errorCb(null);
		cb(ContentInfo$2.encode(rtsp.timeStampToken, "der"));
	});
}
function getStamp(cert, hashedMessage, query) {
	return new Promise((resolve, reject) => getStampCb(cert, hashedMessage, query, resolve, reject));
}
//#endregion
//#region \0@oxc-project+runtime@0.139.0/helpers/esm/asyncToGenerator.js
function asyncGeneratorStep(n, t, e, r, o, a, c) {
	try {
		var i = n[a](c), u = i.value;
	} catch (n) {
		e(n);
		return;
	}
	i.done ? t(u) : Promise.resolve(u).then(r, o);
}
function _asyncToGenerator(n) {
	return function() {
		var t = this, e = arguments;
		return new Promise(function(r, o) {
			var a = n.apply(t, e);
			function _next(n) {
				asyncGeneratorStep(a, r, o, _next, _throw, "next", n);
			}
			function _throw(n) {
				asyncGeneratorStep(a, r, o, _next, _throw, "throw", n);
			}
			_next(void 0);
		});
	};
}
//#endregion
//#region lib/services/ocsp.js
function requestCB(url, spec, nonce, query, cb) {
	var ocsp = OCSPRequest.encode({ tbsRequest: {
		requestList: [{ reqCert: spec }],
		requestExtensions: [{
			extnID: "OCSPNonce",
			extnValue: nonce
		}]
	} }, "der");
	return query("POST", url, {
		"Content-Type": "application/ocsp-request",
		"Content-Length": ocsp.length
	}, ocsp, function(full, status) {
		if (status !== 200) return cb(null);
		try {
			var rocsp = OCSPResponse.decode(full, "der");
		} catch (e) {
			return cb(null);
		}
		if (rocsp.responseStatus === "successful") cb(OcspResponse.fromBasic(rocsp.responseBytes.response));
		else cb(null);
	});
}
function request(...args) {
	return new Promise((resolve, reject) => {
		requestCB(...args, (ret) => ret ? resolve(ret) : reject(ret));
	});
}
function lookup$1(_x, _x2, _x3, _x4) {
	return _lookup.apply(this, arguments);
}
function _lookup() {
	_lookup = _asyncToGenerator(function* (cert, serial, nonce, ctx) {
		const spec = OcspResponse.encodeSpec(cert, serial, ctx.hashFn);
		return request(cert.ocspLink, spec, nonce, ctx.query);
	});
	return _lookup.apply(this, arguments);
}
//#endregion
//#region lib/services/cmp.js
function makePayload(keyids) {
	var ct = Buffer.alloc(120);
	ct.fill(0);
	keyids[0].copy(ct, 12);
	(keyids[1] || keyids[0]).copy(ct, 44);
	ct[108] = 1;
	ct[112] = 1;
	ct[8] = 2;
	ct[0] = 13;
	return new Message({
		type: "data",
		data: ct
	}).as_asn1();
}
function unpack(resp) {
	var rmsg;
	try {
		rmsg = new Message(resp);
	} catch (e) {
		return null;
	}
	if (!rmsg.info) return null;
	if (rmsg.info.readInt32LE(4) !== 1) return null;
	rmsg = new Message(rmsg.info.slice(8));
	return certificates = rmsg.info.certificate.map(function(certData) {
		return new Certificate(certData);
	});
}
function lookup(keyids, url, query) {
	const payload = makePayload(keyids);
	const headers = { "Content-Length": payload.length };
	return new Promise((resolve, reject) => {
		query("POST", url, headers, payload, (response, status) => {
			if (status !== 200) return reject({
				reason: "http",
				status
			});
			let certificates;
			try {
				certificates = unpack(response);
			} catch (e) {
				console.error("e", e);
			}
			if (!certificates) return reject({ reason: "data" });
			resolve(certificates);
		});
	});
}
//#endregion
//#region lib/app/ctx.js
const CERT_CACHE_CUTOFF_MS = 900 * 1e3;
var ENOKEY = class extends Error {};
const filterComplete = function filterComplete(ob) {
	return ob.cert && ob.priv;
};
const filterUsage = function filterUsage(op, ob) {
	return ob.cert.canUseFor(op);
};
const filterRid = function filterRid(rid, ob) {
	if (!rid) return true;
	if (rid.type === "issuerAndSerialNumber") {
		const rdnQuery = Certificate.formatRDN(rid.value.serialNumber, rid.value.issuer.value);
		return ob.cert.rdnSerial() === rdnQuery;
	}
	return false;
};
var Box = class Box {
	constructor(opts = {}) {
		this.cas = {};
		this.casRDN = {};
		this.certsRDN = {};
		this.certsById = {};
		this.keysById = {};
		this.verifiedCache = {};
		this.certCacheCutoff = CERT_CACHE_CUTOFF_MS;
		this.algo = opts.algo || {};
		this.keys = [];
		if (opts.keys) this.loadMaterial(opts.keys);
		if (opts.casBuffer) this.loadCAs(opts.casBuffer);
		this.query = opts.query || null;
	}
	get ocspCtx() {
		return {
			query: this.query,
			lookupCA: this.lookupCA.bind(this),
			hashFn: this.algo.hash
		};
	}
	loadMaterial(info) {
		for (let datum of info) for (let part of Box.load(datum, this.algo)) this.add(part, this.algo);
		this._indexKeys();
	}
	load(keyinfo) {
		for (let part of Box.load(keyinfo, this.algo)) this.add(part, this.algo);
		this._indexKeys();
	}
	loadCertsCmp(url) {
		var _this = this;
		return _asyncToGenerator(function* () {
			const keyids = _this.keys.filter((info) => info.priv).map((info) => info.priv.pub().keyid(_this.algo));
			const [key0, key1] = keyids;
			const certificates = yield lookup(keyids, url, _this.query);
			let numberAdded = 0;
			for (let cert of certificates) {
				const keyid = cert.extension.subjectKeyIdentifier.toString("hex");
				if (_this.keysById[keyid]) numberAdded += 1;
				_this.add({ cert });
			}
			_this._indexKeys();
			return numberAdded;
		})();
	}
	findCertsCmp(urlsHint) {
		var _this2 = this;
		return _asyncToGenerator(function* () {
			let steps = [];
			if (urlsHint && urlsHint.length) steps = [urlsHint];
			else steps = _this2.getUniqueOCSPUrls().map((url) => [url.replace(/ocsp/, "cmp")]);
			const loadOne = (url) => {
				return _this2.loadCertsCmp(url).catch((e) => 0);
			};
			for (let step of steps) {
				let nonZero = (yield Promise.all(step.map(loadOne))).find((number) => number > 0);
				if (nonZero) return nonZero;
			}
			return 0;
		})();
	}
	getUniqueOCSPUrls() {
		let ret = [];
		if (this._cachedOcspUrls) return this._cachedOcspUrls;
		this._cachedOcspUrls = ret;
		Object.keys(this.cas).forEach((idx) => {
			const calist = this.cas[idx];
			for (let ca of calist) {
				const cert = new Certificate(ca);
				if (!cert.extension.authorityInfoAccess || cert.extension.authorityInfoAccess.id !== "ocsp") continue;
				const url = cert.extension.authorityInfoAccess.link;
				if (url && !ret.includes(url)) ret.push(url);
			}
		});
		return ret;
	}
	_indexKeys() {
		this.keys = Object.entries(this.keysById).map(([keyid, priv]) => ({
			priv,
			cert: this.certsById[keyid] || null,
			keyid
		}));
	}
	_indexCAs() {
		Object.keys(this.cas).forEach((idx) => {
			const calist = this.cas[idx];
			for (let ca of calist) {
				const rdn = Certificate.formatRDN(ca.tbsCertificate.serialNumber, ca.tbsCertificate.issuer.value);
				this.casRDN[rdn] = ca;
			}
		});
	}
	loadCAs(buffer) {
		const msg = new Message(buffer);
		for (let certOb of msg.info.certificate) {
			certOb.trusted = true;
			let query = Certificate.formatDN(certOb.tbsCertificate.subject.value);
			this.cas[query] = (this.cas[query] || []).concat([certOb]);
		}
		this._indexCAs();
		this._indexKeys();
		this.hasCA = true;
	}
	lookupCA(query, keyId) {
		for (let ca of this.cas[query] || []) {
			let cert = new Certificate(ca);
			cert.trusted = true;
			if (!keyId || cert.extension.subjectKeyIdentifier.equals(keyId)) return cert;
		}
		return null;
	}
	lookupByKeyId(helpCerts, keyId) {
		for (let cert of helpCerts) if (cert.extension.subjectKeyIdentifier.equals(keyId)) return cert;
		throw new Message.ENOCERT();
	}
	lookupCert(helpCerts, query) {
		if (query.keyid) return this.lookupByKeyId(helpCerts, query.keyid);
		const rdnQuery = Certificate.formatRDN(query.serialNumber, query.issuer.value);
		for (let cert of helpCerts) if (cert.rdnSerial() === rdnQuery) return cert;
		let ret = this.certsRDN[rdnQuery] || this.casRDN[rdnQuery];
		if (ret && ret.format !== "x509") {
			ret = new Certificate(ret);
			ret.trusted = Boolean(ret.trusted);
		}
		return ret || null;
	}
	lookupIssuedBy(query) {
		for (let list of Object.values(this.cas)) for (let cert of list) if (Certificate.formatDN(cert.tbsCertificate.issuer.value) === query) return new Certificate(cert);
	}
	verifyCert(cert, time, usage) {
		const lastViable = Date.now() - this.certCacheCutoff;
		const sid = cert.extension.subjectKeyIdentifier;
		const sidHex = sid ? sid.toString("hex") : null;
		let cachedRes = sidHex && this.verifiedCache.hasOwnProperty(sidHex) ? this.verifiedCache[sidHex] : null;
		if (cachedRes && cachedRes.ctime < lastViable) {
			cachedRes = null;
			delete this.verifiedCache[sidHex];
		}
		if (cachedRes && !cachedRes.ret) return false;
		if (cachedRes && cachedRes.ret === true) return (usage ? cert.canUseFor(usage) : true) && cert.verifyTime(Number(time));
		const ret = cert.verify({
			time,
			usage
		}, { Dstu4145le: this.algo.hash }, this.lookupCA.bind(this));
		this.verifiedCache[sidHex] = {
			ret,
			ctime: Date.now()
		};
		return ret;
	}
	lookupCertOrSibling(lookup, query) {
		let cert = lookup(query);
		if (!cert) {
			const issuer = this.lookupCA(Certificate.formatDN(query.issuer.value));
			cert = issuer && this.lookupIssuedBy(issuer.subjectDN());
		}
		return cert;
	}
	lookupOCSP(lookup, query, msg) {
		var _this3 = this;
		return _asyncToGenerator(function* () {
			const cert = _this3.lookupCertOrSibling(lookup, query);
			if (!cert) return {
				statusOk: false,
				unknown: true
			};
			const ocspCtx = _this3.ocspCtx;
			let response = msg.puattrs.revocationValues.find((iterResponse) => iterResponse.matches(cert, query.serialNumber, ocspCtx));
			let nonce;
			const isOcspStamp = Boolean(response);
			if (response) nonce = null;
			else {
				nonce = rand_default(Buffer.alloc(20));
				try {
					response = yield lookup$1(cert, query.serialNumber, nonce, ocspCtx);
				} catch (e) {}
			}
			if (!response) return {
				statusOk: false,
				unknown: true
			};
			try {
				return response.verify(ocspCtx, cert, query.serialNumber, nonce, isOcspStamp);
			} catch (e) {
				return { statusOk: false };
			}
		})();
	}
	add({ cert, priv }) {
		if (!cert && !priv) return;
		const keyid = (cert ? cert.pubkey : priv.pub()).keyid(this.algo).toString("hex");
		if (cert) {
			this.certsById[keyid] = cert;
			this.certsRDN[cert.rdnSerial()] = cert;
		}
		if (priv) this.keysById[keyid] = priv;
	}
	sign(data, role, unusedCert, opts) {
		var _this4 = this;
		return _asyncToGenerator(function* () {
			const key = _this4.keyFor("sign", role);
			const dataHash = _this4.algo.hash(data);
			let tspB;
			if (useContentTsp(opts.tsp)) tspB = yield getStamp(key.cert, dataHash, _this4.query);
			const message = new Message({
				type: "signedData",
				cert: key.cert,
				data: opts.detached ? null : data,
				dataHash,
				signer: key.priv,
				hash: _this4.algo.hash,
				tspB,
				signTime: opts.time
			});
			if (useSignatureTsp(opts.tsp)) {
				const signHash = _this4.algo.hash(message.signature);
				tspB = yield getStamp(key.cert, signHash, _this4.query);
				message.addSignatureToken(tspB);
			}
			if (opts.includeChain) {
				const chain = key.cert.getCompleteChain(_this4.lookupCA.bind(_this4));
				message.addCertRefs(chain.map((cert) => CertificateRef.fromCert(cert, _this4.algo.hash)));
				if (opts.includeChain !== "ref") message.addCertValues(chain);
			}
			if (opts.ocsp) {
				let ocspResponses = yield Promise.all(message.signedWithCerts.map(function() {
					var _ref = _asyncToGenerator(function* (query) {
						const lookup = _this4.lookupCert.bind(_this4, [key.cert]);
						const cert = _this4.lookupCertOrSibling(lookup, query);
						if (!cert) return null;
						const nonce = rand_default(Buffer.alloc(20));
						const response = yield lookup$1(cert, query.serialNumber || cert.serial, nonce, _this4.ocspCtx);
						if (!response.verify(_this4.ocspCtx, cert, query.serialNumber, nonce, false).statusOk) return null;
						return response;
					});
					return function(_x) {
						return _ref.apply(this, arguments);
					};
				}()));
				ocspResponses = ocspResponses.filter((iter) => iter);
				message.addOcspHashes(ocspResponses.map((iter) => [iter.makeRef(_this4.ocspCtx)]));
				if (opts.ocsp !== "ref") message.addOcspResponses(ocspResponses);
			}
			return message;
		})();
	}
	encrypt(data, role, forCert, opts) {
		if (forCert === void 0) throw new Error("No recipient specified for encryption");
		const key = this.keyFor("encrypt", role);
		return new Message({
			type: "envelopedData",
			cert: key.cert,
			toCert: forCert,
			data,
			crypter: key.priv,
			algo: this.algo
		});
	}
	keyFor(op, role, query) {
		const [firstKey] = this.keys.filter(filterComplete).filter(filterRid.bind(null, query)).filter(filterUsage.bind(null, op));
		if (!firstKey || !firstKey.priv) throw new ENOKEY(`No key-certificate pair found for given op ${op}`, { op });
		return firstKey;
	}
	pipe(data, commands, opts, cb) {
		var _this5 = this;
		return _asyncToGenerator(function* () {
			let [cmd, ...restCommands] = commands;
			if (!cmd) return data;
			if (typeof cmd === "string") cmd = { op: cmd };
			if (cmd.op === void 0) throw new Error("Broken pipeline element", cmd);
			let cert = cmd.forCert;
			if (typeof cert === "string") cert = Certificate.from_pem(cert);
			const msg = yield _this5[cmd.op](data, cmd.role, cert, cmd);
			return _this5.pipe(cmd.tax ? msg.as_transport(opts, cmd.addCert) : msg.as_asn1(), restCommands, opts);
		})();
	}
	unwrap(_x2, _x3) {
		var _this6 = this;
		return _asyncToGenerator(function* (data, content, opts = {}) {
			let msg;
			let x;
			const info = { pipe: [] };
			let tr;
			let signed;
			let key;
			let help_cert = [];
			const lookup = (query) => _this6.lookupCert(help_cert, query);
			while (data && data.length) {
				try {
					tr = transport_default.decode(data);
				} catch (e) {
					tr = null;
				}
				if (tr) {
					if (tr.header) info.pipe.push({
						transport: true,
						headers: tr.header
					});
					msg = tr.docs.shift();
					while (msg.type === "CERTCRYPT") {
						help_cert.push(Certificate.from_asn1(msg.contents));
						msg = tr.docs.shift();
					}
					if (msg.type.substr(3) === "_CRYPT" || msg.type.substr(3) === "_SIGN") data = msg.contents;
					if (msg.type.substr(0, 3) === "QLB" && tr.docs.length > 0) content = tr.docs.shift().contents;
					if (msg.type === "DOCUMENT" && msg.encoding === "PACKED_XML_DOCUMENT") {
						data = msg.contents;
						continue;
					}
				}
				try {
					msg = new Message(data);
				} catch (e) {
					if (tr === null) break;
					throw e;
				}
				if (msg.type === "signedData") {
					if (msg.info.contentInfo.content === void 0) {
						if (content === void 0) {
							info.pipe.push({ error: "ENODATA" });
							break;
						}
						msg.info.contentInfo.content = content;
					}
					try {
						help_cert.push(msg.signer(lookup));
					} catch (e) {
						if (!(e instanceof Message.ENOCERT)) throw e;
					}
					let ocspResult;
					if (opts.ocsp) {
						ocspResult = yield Promise.all(msg.signedWithCerts.map((query) => _this6.lookupOCSP(lookup, query, msg)));
						if (opts.ocsp === "lax" ? !ocspResult.every((ocsp) => ocsp.statusOk || !ocsp.requestOK) : !ocspResult.every((ocsp) => ocsp.statusOk)) {
							info.pipe.push({
								broken_cert: true,
								error: "EOCSP"
							});
							break;
						}
						let discoveredCerts = ocspResult.filter((ocsp) => ocsp.statusOk && ocsp.cert).map((ocsp) => new Certificate(ocsp.cert));
						help_cert = [...help_cert, ...discoveredCerts];
					}
					try {
						signed = msg.verify(_this6.algo.hash, lookup, _this6.lookupCA.bind(_this6), opts);
						x = msg.signer(lookup);
						if (!x.canUseFor("sign")) throw new Message.ENOCERT();
					} catch (e) {
						if (!(e instanceof Message.ENOCERT)) throw e;
						info.pipe.push({
							signed: true,
							error: "ENOCERT"
						});
						break;
					}
					if (signed !== true) {
						info.pipe.push({
							broken_sign: true,
							error: "ESIGN"
						});
						break;
					}
					data = msg.info.contentInfo.content;
					let entry = {
						signed,
						ocsp: ocspResult,
						cert: x.as_dict(),
						signingTime: msg.pattrs.signingTime,
						contentTime: useContentTsp(opts.tsp) && msg.contentTime || null,
						tokenTime: useSignatureTsp(opts.tsp) && msg.tokenTime || null
					};
					let time = entry.tokenTime || entry.contentTime || entry.signingTime || Date.now();
					if (_this6.hasCA) {
						entry.cert.verified = _this6.verifyCert(x, time, "sign");
						if (!entry.cert.verified) {
							info.pipe.push({
								broken_cert: true,
								error: "ESIGN"
							});
							break;
						}
					}
					help_cert.push(x);
					info.pipe.push(entry);
				}
				if (msg.type === "envelopedData") {
					try {
						key = _this6.keyFor("encrypt", null, msg.receiverKey);
					} catch (e) {
						if (!(e instanceof ENOKEY)) throw e;
						info.pipe.push({
							enc: true,
							error: "ENOKEY"
						});
						break;
					}
					info.pipe.push({ enc: true });
					try {
						data = msg.decrypt(key.priv, _this6.algo, lookup);
					} catch (e) {
						if (!(e instanceof Message.ENOCERT)) throw e;
						info.pipe.push({
							enc: true,
							error: "ENOCERT"
						});
						break;
					}
				}
			}
			info.content = data;
			if (info.pipe.length && info.pipe[info.pipe.length - 1].error) info.error = info.pipe[info.pipe.length - 1].error;
			return info;
		}).apply(this, arguments);
	}
};
Box.load = load;
Box.EOLD = EOLD;
//#endregion
//#region lib/index.js
var lib_default = Box;
//#endregion
exports.Box = Box;
exports.Certificate = Certificate;
exports.Curve = Curve;
exports.Field = Field;
exports.Keycoder = Keycoder;
exports.Priv = Priv;
exports.Pub = Pub;
exports.b64_decode = b64_decode;
exports.b64_encode = b64_encode;
exports.default = lib_default;
Object.defineProperty(exports, "dstszi2010", {
	enumerable: true,
	get: function() {
		return dstszi2010_exports;
	}
});
exports.guess_parse = guess_parse;
Object.defineProperty(exports, "models", {
	enumerable: true,
	get: function() {
		return models_exports;
	}
});
exports.pkey = pkey;
exports.pubkey = pubkey;
exports.rfc3161 = rfc3161_tsp_default;
Object.defineProperty(exports, "rfc3280", {
	enumerable: true,
	get: function() {
		return rfc3280_exports;
	}
});
Object.defineProperty(exports, "standard", {
	enumerable: true,
	get: function() {
		return standard_exports;
	}
});
exports.std_curve = std_curve;
exports.transport = transport_default;
