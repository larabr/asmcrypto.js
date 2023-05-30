// shared asm.js module and heap
import { AES_asm } from './aes.asm.js';

export var _AES_heap_instance = new Uint8Array(0x100000); // 1MB
export var _AES_asm_instance = new AES_asm(null, _AES_heap_instance.buffer);
