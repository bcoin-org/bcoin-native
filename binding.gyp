{
  "targets": [{
    "target_name": "bcoin-native",
    "sources": [
      "./src/poly1305-donna/poly1305-donna.c",
      "./src/chacha20-simple/chacha20_simple.c",
      "./src/scrypt/insecure_memzero.c",
      "./src/scrypt/sha256.c",
      "./src/scrypt/crypto_scrypt.c",
      "./src/chacha20.cc",
      "./src/poly1305.cc",
      "./src/digest.cc",
      "./src/cipher.cc",
      "./src/base58.cc",
      "./src/bech32.cc",
      "./src/scrypt.cc",
      "./src/scrypt_async.cc",
      "./src/murmur3.cc",
      "./src/siphash.cc",
      "./src/bcn.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wno-implicit-fallthrough",
      "-Wno-maybe-uninitialized",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wextra",
      "-O3"
    ],
    "cflags_c": [
      "-std=c99"
    ],
    "cflags_cc+": [
      "-std=c++0x"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")"
    ],
    "variables": {
      "conditions": [
        ["OS=='win'", {
          "conditions": [
            ["target_arch=='ia32'", {
              "openssl_root%": "C:/OpenSSL-Win32"
            }, {
              "openssl_root%": "C:/OpenSSL-Win64"
            }]
          ]
        }]
      ]
    },
    "conditions": [
      ["target_arch=='x64' and OS!='win'", {
        "defines": [
          "POLY1305_64BIT"
        ]
      }, {
        "defines": [
          "POLY1305_32BIT"
        ]
      }],
      ["OS=='win'", {
        "libraries": [
          "-l<(openssl_root)/lib/libeay32.lib",
        ],
        "include_dirs": [
          "<(openssl_root)/include",
        ]
      }, {
        "include_dirs": [
          "<(node_root_dir)/deps/openssl/openssl/include"
        ]
      }]
    ]
  }]
}
