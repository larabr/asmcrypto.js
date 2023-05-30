import { AES_ECB } from '@openpgp/asmcrypto.js/aes/ecb.js';
import { AES_CBC } from '@openpgp/asmcrypto.js/aes/cbc.js';
import { AES_CFB } from '@openpgp/asmcrypto.js/aes/cfb.js';
import { AES_GCM } from '@openpgp/asmcrypto.js/aes/gcm.js';
import { AES_CTR } from '@openpgp/asmcrypto.js/aes/ctr.js';
import * as utils from '../dist/other/utils.js';
import { expect } from 'chai';
import { Buffer } from 'buffer';

function base64_to_bytes(str) {
  return utils.string_to_bytes(Buffer.from(str, 'base64').toString('binary'));
}

describe('AES', () => {
  describe('ECB', () => {
    const ecb_aes_vectors = [
      // AES-ECB-128
      [
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        '6bc1bee22e409f96e93d7e117393172a', // clear text
        '3ad77bb40d7a3660a89ecaf32466ef97', // cipher text
      ],
      [
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        'ae2d8a571e03ac9c9eb76fac45af8e51', // clear text
        'f5d3d58503b9699de785895a96fdbaaf', // cipher text
      ],
      [
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        '30c81c46a35ce411e5fbc1191a0a52ef', // clear text
        '43b1cd7f598ece23881b00e3ed030688', // cipher text
      ],
      [
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        'f69f2445df4f9b17ad2b417be66c3710', // clear text
        '7b0c785e27e8ad3f8223207104725dd4', // cipher text
      ],
      [
        // Two blocks
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        'f69f2445df4f9b17ad2b417be66c3710f69f2445df4f9b17ad2b417be66c3710', // clear text
        '7b0c785e27e8ad3f8223207104725dd47b0c785e27e8ad3f8223207104725dd4', // cipher text
      ],
      // AES-ECB-256
      [
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        '6bc1bee22e409f96e93d7e117393172a', // clear text
        'f3eed1bdb5d2a03c064b5a7e3db181f8', // cipher text
      ],
      [
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        'ae2d8a571e03ac9c9eb76fac45af8e51', // clear text
        '591ccb10d410ed26dc5ba74a31362870', // cipher text
      ],
      [
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        '30c81c46a35ce411e5fbc1191a0a52ef', // clear text
        'b6ed21b99ca6f4f9f153e7b1beafed1d', // cipher text
      ],
      [
        // Two blocks
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        '30c81c46a35ce411e5fbc1191a0a52ef30c81c46a35ce411e5fbc1191a0a52ef', // clear text
        'b6ed21b99ca6f4f9f153e7b1beafed1db6ed21b99ca6f4f9f153e7b1beafed1d', // cipher text
      ],
      [
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        'f69f2445df4f9b17ad2b417be66c3710', // clear text
        '23304b7a39f9f3ff067d8d8f9e24ecc7', // cipher text
      ],
    ];

    it('AES_ECB.encrypt / AES_ECB.decrypt', function () {
      for (let i = 0; i < ecb_aes_vectors.length; ++i) {
        const key = new Uint8Array(utils.hex_to_bytes(ecb_aes_vectors[i][0]));
        const clear = new Uint8Array(utils.hex_to_bytes(ecb_aes_vectors[i][1]));
        const cipher = new Uint8Array(utils.hex_to_bytes(ecb_aes_vectors[i][2]));

        expect(AES_ECB.encrypt(clear, key), `encrypt vector ${i}`).to.deep.equal(cipher);

        expect(AES_ECB.decrypt(cipher, key), `decrypt vector ${i}`).to.deep.equal(clear);
      }
    });
  });

  describe('CBC', () => {
    const cbc_aes_vectors = [
      [   // key
        [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        // cipher text
        [0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
          0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
          0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
          0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7]
      ],
      [   // key
        [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
          0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        // cipher text
        [0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
          0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
          0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
          0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b]
      ]
    ];

    it('AES_CBC.encrypt / AES_CBC.decrypt', function () {
      for (let i = 0; i < cbc_aes_vectors.length; ++i) {
        const key = new Uint8Array(cbc_aes_vectors[i][0]);
        const iv = new Uint8Array(cbc_aes_vectors[i][1]);
        const clear = new Uint8Array(cbc_aes_vectors[i][2]);
        const cipher = new Uint8Array(cbc_aes_vectors[i][3]);

        expect(utils.bytes_to_hex(AES_CBC.encrypt(clear, key, false, iv)), `encrypt vector ${i}`).to.be.equal(utils.bytes_to_hex(cipher));

        expect(utils.bytes_to_hex(AES_CBC.decrypt(cipher, key, false, iv)), `decrypt vector ${i}`).to.be.equal(utils.bytes_to_hex(clear));
      }
    });
  });

  describe('CTR', () => {
    const ctr_aes_vectors = [
      [
        // key
        utils.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        // nonce
        utils.hex_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
        // input message
        utils.hex_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'),
        // encrypted message
        utils.hex_to_bytes('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee')
      ],
      [
        // key
        utils.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        // nonce
        utils.hex_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
        // input message
        utils.hex_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c'),
        // encrypted message
        utils.hex_to_bytes('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f300')
      ],
      [
        // key
        utils.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        // nonce
        utils.hex_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
        // input message
        utils.hex_to_bytes('6bc1bee22e409f96e93d7e11739317'),
        // encrypted message
        utils.hex_to_bytes('874d6191b620e3261bef6864990db6')
      ],
      [
        // key
        utils.hex_to_bytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'),
        // nonce
        utils.hex_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
        // input message
        utils.hex_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'),
        // encrypted message
        utils.hex_to_bytes('601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6')
      ]
    ];

    it('AES_CTR.encrypt / AES_CTR.decrypt', function () {
      for (let i = 0; i < ctr_aes_vectors.length; ++i) {
        const key = new Uint8Array(ctr_aes_vectors[i][0]);
        const nonce = new Uint8Array(ctr_aes_vectors[i][1]);
        const clear = new Uint8Array(ctr_aes_vectors[i][2]);
        const cipher = new Uint8Array(ctr_aes_vectors[i][3]);

        expect(utils.bytes_to_hex(AES_CTR.encrypt(clear, key, nonce)), `encrypt vector ${i}`).to.be.equal(utils.bytes_to_hex(cipher));

        expect(utils.bytes_to_hex(AES_CTR.decrypt(cipher, key, nonce)), `decrypt vector ${i}`).to.be.equal(utils.bytes_to_hex(clear));
      }
    });
  });
  describe('GCM', () => {
    const gcm_aes_vectors = [
      [
        // key
        utils.hex_to_bytes('00000000000000000000000000000000'),
        // nonce
        utils.hex_to_bytes('000000000000000000000000'),
        // adata
        undefined,
        // tagSize
        16,
        // input message
        utils.string_to_bytes(''),
        // encrypted message
        utils.hex_to_bytes('58e2fccefa7e3061367f1d57a4e7455a')
      ],
      [
        // key
        utils.hex_to_bytes('00000000000000000000000000000000'),
        // nonce
        utils.hex_to_bytes('000000000000000000000000'),
        // adata
        utils.string_to_bytes(''),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes('00000000000000000000000000000000'),
        // encrypted message
        utils.hex_to_bytes('0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf')
      ],
      [
        // key
        utils.hex_to_bytes('feffe9928665731c6d6a8f9467308308'),
        // nonce
        utils.hex_to_bytes('cafebabefacedbaddecaf888'),
        // adata
        utils.string_to_bytes(''),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'),
        // encrypted message
        utils.hex_to_bytes('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4')
      ],
      [
        // key
        utils.hex_to_bytes('feffe9928665731c6d6a8f9467308308'),
        // nonce
        utils.hex_to_bytes('cafebabefacedbaddecaf888'),
        // adata
        utils.hex_to_bytes('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'),
        // encrypted message
        utils.hex_to_bytes('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47')
      ],
      [
        // key
        utils.hex_to_bytes('feffe9928665731c6d6a8f9467308308'),
        // nonce
        utils.hex_to_bytes('cafebabefacedbad'),
        // adata
        utils.hex_to_bytes('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'),
        // encrypted message
        utils.hex_to_bytes('61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f45983612d2e79e3b0785561be14aaca2fccb')
      ],
      [
        // key
        utils.hex_to_bytes('feffe9928665731c6d6a8f9467308308'),
        // nonce
        utils.hex_to_bytes('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b'),
        // adata
        utils.hex_to_bytes('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'),
        // encrypted message
        utils.hex_to_bytes('8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5619cc5aefffe0bfa462af43c1699d050')
      ],
      [
        // key
        utils.hex_to_bytes('0000000000000000000000000000000000000000000000000000000000000000'),
        // nonce
        utils.hex_to_bytes('000000000000000000000000'),
        // adata
        utils.string_to_bytes(''),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes('00000000000000000000000000000000'),
        // encrypted message
        utils.hex_to_bytes('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919')
      ],
      [
        // key
        utils.hex_to_bytes('0000000000000000000000000000000000000000000000000000000000000000'),
        // nonce
        utils.hex_to_bytes('000000000000000000000000'),
        // adata
        utils.string_to_bytes(''),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes(''),
        // encrypted message
        utils.hex_to_bytes('530f8afbc74536b9a963b4f1c4cb738b')
      ],
      [
        // key
        utils.hex_to_bytes('0000000000000000000000000000000000000000000000000000000000000000'),
        // nonce
        utils.hex_to_bytes('000000000000000000000000'),
        // adata
        utils.string_to_bytes(''),
        // tagSize
        16,
        // input message
        utils.string_to_bytes(''),
        // encrypted message
        utils.hex_to_bytes('530f8afbc74536b9a963b4f1c4cb738b')
      ],
      [
        // key
        utils.hex_to_bytes('0000000000000000000000000000000000000000000000000000000000000000'),
        // nonce
        utils.hex_to_bytes('000000000000000000000000'),
        // adata
        utils.string_to_bytes(''),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes('00000000000000000000000000000000'),
        // encrypted message
        utils.hex_to_bytes('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919')
      ],
      [
        // key
        utils.hex_to_bytes('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'),
        // nonce
        utils.hex_to_bytes('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b'),
        // adata
        utils.hex_to_bytes('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'),
        // encrypted message
        utils.hex_to_bytes('5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3fa44a8266ee1c8eb0c8b5d4cf5ae9f19a')
      ],
      [ // Test case for issue #70 (https://github.com/vibornoff/utils.js/issues/70)
        // key
        utils.hex_to_bytes('00000000000000000000000000000000'),
        // nonce
        utils.hex_to_bytes('00'),
        // adata
        utils.string_to_bytes(''),
        // tagSize
        16,
        // input message
        utils.hex_to_bytes('00'),
        // encrypted message
        utils.hex_to_bytes('e9d60634580263ebab909efa6623dafc61')
      ],
      [ // Test case for issue #70 (https://github.com/vibornoff/utils.js/issues/92)
        // key
        base64_to_bytes('dGQhii+B7+eLLHRiOA690w=='),
        // nonce
        base64_to_bytes('R8q1njARXS7urWv3'),
        // adata
        undefined,
        // tagSize
        16,
        // input message
        base64_to_bytes('dGQhwoovwoHDr8OnwossdGI4DsK9w5M='),
        // encrypted message
        base64_to_bytes('L3zqVYAOsRk7zMg2KsNTVShcad8TjIQ7umfsvia21QO0XTj8vaeR')
      ],
    ];

    it("AES_GCM.encrypt", function () {
      for (let i = 0; i < gcm_aes_vectors.length; ++i) {
        const key = gcm_aes_vectors[i][0];
        const nonce = gcm_aes_vectors[i][1];
        const adata = gcm_aes_vectors[i][2];
        const tagsize = gcm_aes_vectors[i][3];
        const cleartext = gcm_aes_vectors[i][4];
        const ciphertext = gcm_aes_vectors[i][5];

        expect(utils.bytes_to_hex(AES_GCM.encrypt(cleartext, key, nonce, adata, tagsize)), 'encrypt vector ' + i).to.be.equal(utils.bytes_to_hex(ciphertext));

        expect(utils.bytes_to_hex(AES_GCM.decrypt(ciphertext, key, nonce, adata, tagsize)), 'decrypt vector ' + i).to.be.equal(utils.bytes_to_hex(cleartext));
      }
    });
  });

  describe('CFB', () => {
    const cfb_aes_vectors = [
      [   // key
        [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        // cipher text
        [0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
          0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
          0x26, 0x75, 0x1f, 0x67, 0xa3, 0xcb, 0xb1, 0x40, 0xb1, 0x80, 0x8c, 0xf1, 0x87, 0xa4, 0xf4, 0xdf,
          0xc0, 0x4b, 0x05, 0x35, 0x7c, 0x5d, 0x1c, 0x0e, 0xea, 0xc4, 0xc6, 0x6f, 0x9f, 0xf7, 0xf2, 0xe6]
      ],
      [   // key
        [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41],
        // cipher text
        [0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
          0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
          0x26, 0x75, 0x1f, 0x67, 0xa3, 0xcb, 0xb1, 0x40, 0xb1, 0x80, 0x8c, 0xf1, 0x87, 0xa4, 0xf4, 0xdf,
          0xc0, 0x4b, 0x05, 0x35, 0x7c, 0x5d, 0x1c, 0x0e, 0xea, 0xc4, 0xc6]
      ],
      [   // key
        [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
          0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        // cipher text
        [0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, 0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
          0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8, 0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b,
          0xdf, 0x10, 0x13, 0x24, 0x15, 0xe5, 0x4b, 0x92, 0xa1, 0x3e, 0xd0, 0xa8, 0x26, 0x7a, 0xe2, 0xf9,
          0x75, 0xa3, 0x85, 0x74, 0x1a, 0xb9, 0xce, 0xf8, 0x20, 0x31, 0x62, 0x3d, 0x55, 0xb1, 0xe4, 0x71]
      ],
      [   // key
        [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
          0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24],
        // cipher text
        [0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, 0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
          0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8, 0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b,
          0xdf, 0x10, 0x13, 0x24, 0x15, 0xe5, 0x4b, 0x92, 0xa1, 0x3e, 0xd0, 0xa8, 0x26, 0x7a, 0xe2, 0xf9,
          0x75, 0xa3, 0x85]
      ]
    ];

    it('AES_CFB.encrypt / AES_CFB.decrypt', function () {
      for (let i = 0; i < cfb_aes_vectors.length; ++i) {
        const key = new Uint8Array(cfb_aes_vectors[i][0]);
        const iv = new Uint8Array(cfb_aes_vectors[i][1]);
        const clear = new Uint8Array(cfb_aes_vectors[i][2]);
        const cipher = new Uint8Array(cfb_aes_vectors[i][3]);

        expect(utils.bytes_to_hex(AES_CFB.encrypt(clear, key, iv)), `encrypt vector ${i}`).to.be.equal(utils.bytes_to_hex(cipher));

        expect(utils.bytes_to_hex(AES_CFB.decrypt(cipher, key, iv)), `decrypt vector ${i}`).to.be.equal(utils.bytes_to_hex(clear));
      }
    });
  });
});
