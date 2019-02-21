(function() {
    var wasm;
    const __exports = {};


    let cachedTextEncoder = new TextEncoder('utf-8');

    let cachegetUint8Memory = null;
    function getUint8Memory() {
        if (cachegetUint8Memory === null || cachegetUint8Memory.buffer !== wasm.memory.buffer) {
            cachegetUint8Memory = new Uint8Array(wasm.memory.buffer);
        }
        return cachegetUint8Memory;
    }

    let WASM_VECTOR_LEN = 0;

    function passStringToWasm(arg) {

        const buf = cachedTextEncoder.encode(arg);
        const ptr = wasm.__wbindgen_malloc(buf.length);
        getUint8Memory().set(buf, ptr);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    function passArray8ToWasm(arg) {
        const ptr = wasm.__wbindgen_malloc(arg.length * 1);
        getUint8Memory().set(arg, ptr / 1);
        WASM_VECTOR_LEN = arg.length;
        return ptr;
    }

    let cachedTextDecoder = new TextDecoder('utf-8');

    function getStringFromWasm(ptr, len) {
        return cachedTextDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
    }

    let cachedGlobalArgumentPtr = null;
    function globalArgumentPtr() {
        if (cachedGlobalArgumentPtr === null) {
            cachedGlobalArgumentPtr = wasm.__wbindgen_global_argument_ptr();
        }
        return cachedGlobalArgumentPtr;
    }

    let cachegetUint32Memory = null;
    function getUint32Memory() {
        if (cachegetUint32Memory === null || cachegetUint32Memory.buffer !== wasm.memory.buffer) {
            cachegetUint32Memory = new Uint32Array(wasm.memory.buffer);
        }
        return cachegetUint32Memory;
    }

    function getArrayU8FromWasm(ptr, len) {
        return getUint8Memory().subarray(ptr / 1, ptr / 1 + len);
    }

    const u32CvtShim = new Uint32Array(2);

    const uint64CvtShim = new BigUint64Array(u32CvtShim.buffer);

    function freeEcc(ptr) {

        wasm.__wbg_ecc_free(ptr);
    }
    /**
    */
    class Ecc {

        static __wrap(ptr) {
            const obj = Object.create(Ecc.prototype);
            obj.ptr = ptr;

            return obj;
        }

        free() {
            const ptr = this.ptr;
            this.ptr = 0;
            freeEcc(ptr);
        }

        /**
        * @param {string} arg0
        * @returns {Ecc}
        */
        static from_seed(arg0) {
            const ptr0 = passStringToWasm(arg0);
            const len0 = WASM_VECTOR_LEN;
            try {
                return Ecc.__wrap(wasm.ecc_from_seed(ptr0, len0));

            } finally {
                wasm.__wbindgen_free(ptr0, len0 * 1);

            }

        }
        /**
        * @param {Uint8Array} arg0
        * @returns {Ecc}
        */
        static from_buffer(arg0) {
            const ptr0 = passArray8ToWasm(arg0);
            const len0 = WASM_VECTOR_LEN;
            try {
                return Ecc.__wrap(wasm.ecc_from_buffer(ptr0, len0));

            } finally {
                wasm.__wbindgen_free(ptr0, len0 * 1);

            }

        }
        /**
        * @returns {string}
        */
        to_wif() {
            const retptr = globalArgumentPtr();
            wasm.ecc_to_wif(retptr, this.ptr);
            const mem = getUint32Memory();
            const rustptr = mem[retptr / 4];
            const rustlen = mem[retptr / 4 + 1];

            const realRet = getStringFromWasm(rustptr, rustlen).slice();
            wasm.__wbindgen_free(rustptr, rustlen * 1);
            return realRet;

        }
        /**
        * @param {string} arg0
        * @returns {string}
        */
        to_public_str(arg0) {
            const ptr0 = passStringToWasm(arg0);
            const len0 = WASM_VECTOR_LEN;
            const retptr = globalArgumentPtr();
            try {
                wasm.ecc_to_public_str(retptr, this.ptr, ptr0, len0);
                const mem = getUint32Memory();
                const rustptr = mem[retptr / 4];
                const rustlen = mem[retptr / 4 + 1];

                const realRet = getStringFromWasm(rustptr, rustlen).slice();
                wasm.__wbindgen_free(rustptr, rustlen * 1);
                return realRet;


            } finally {
                wasm.__wbindgen_free(ptr0, len0 * 1);

            }

        }
        /**
        * @param {string} arg0
        * @returns {string}
        */
        sign_hex(arg0) {
            const ptr0 = passStringToWasm(arg0);
            const len0 = WASM_VECTOR_LEN;
            const retptr = globalArgumentPtr();
            try {
                wasm.ecc_sign_hex(retptr, this.ptr, ptr0, len0);
                const mem = getUint32Memory();
                const rustptr = mem[retptr / 4];
                const rustlen = mem[retptr / 4 + 1];

                const realRet = getStringFromWasm(rustptr, rustlen).slice();
                wasm.__wbindgen_free(rustptr, rustlen * 1);
                return realRet;


            } finally {
                wasm.__wbindgen_free(ptr0, len0 * 1);

            }

        }
        /**
        * @param {Uint8Array} arg0
        * @returns {Uint8Array}
        */
        sign_buffer(arg0) {
            const ptr0 = passArray8ToWasm(arg0);
            const len0 = WASM_VECTOR_LEN;
            const retptr = globalArgumentPtr();
            try {
                wasm.ecc_sign_buffer(retptr, this.ptr, ptr0, len0);
                const mem = getUint32Memory();
                const rustptr = mem[retptr / 4];
                const rustlen = mem[retptr / 4 + 1];

                const realRet = getArrayU8FromWasm(rustptr, rustlen).slice();
                wasm.__wbindgen_free(rustptr, rustlen * 1);
                return realRet;


            } finally {
                wasm.__wbindgen_free(ptr0, len0 * 1);

            }

        }
        /**
        * @param {Uint8Array} arg0
        * @returns {string}
        */
        sign_buffer_to_hex(arg0) {
            const ptr0 = passArray8ToWasm(arg0);
            const len0 = WASM_VECTOR_LEN;
            const retptr = globalArgumentPtr();
            try {
                wasm.ecc_sign_buffer_to_hex(retptr, this.ptr, ptr0, len0);
                const mem = getUint32Memory();
                const rustptr = mem[retptr / 4];
                const rustlen = mem[retptr / 4 + 1];

                const realRet = getStringFromWasm(rustptr, rustlen).slice();
                wasm.__wbindgen_free(rustptr, rustlen * 1);
                return realRet;


            } finally {
                wasm.__wbindgen_free(ptr0, len0 * 1);

            }

        }
        /**
        * @param {string} arg0
        * @param {BigInt} arg1
        * @param {string} arg2
        * @returns {string}
        */
        decode_memo(arg0, arg1, arg2) {
            const ptr0 = passStringToWasm(arg0);
            const len0 = WASM_VECTOR_LEN;

            uint64CvtShim[0] = arg1;
            const low1 = u32CvtShim[0];
            const high1 = u32CvtShim[1];

            const ptr2 = passStringToWasm(arg2);
            const len2 = WASM_VECTOR_LEN;
            const retptr = globalArgumentPtr();
            try {
                wasm.ecc_decode_memo(retptr, this.ptr, ptr0, len0, low1, high1, ptr2, len2);
                const mem = getUint32Memory();
                const rustptr = mem[retptr / 4];
                const rustlen = mem[retptr / 4 + 1];

                const realRet = getStringFromWasm(rustptr, rustlen).slice();
                wasm.__wbindgen_free(rustptr, rustlen * 1);
                return realRet;


            } finally {
                wasm.__wbindgen_free(ptr0, len0 * 1);
                wasm.__wbindgen_free(ptr2, len2 * 1);

            }

        }
    }
    __exports.Ecc = Ecc;

    __exports.__wbindgen_throw = function(ptr, len) {
        throw new Error(getStringFromWasm(ptr, len));
    };

    function init(path_or_module) {
        let instantiation;
        const imports = { './cybex_ecc': __exports };
        if (path_or_module instanceof WebAssembly.Module) {
            instantiation = WebAssembly.instantiate(path_or_module, imports)
            .then(instance => {
            return { instance, module: path_or_module }
        });
    } else {
        const data = fetch(path_or_module);
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            instantiation = WebAssembly.instantiateStreaming(data, imports);
        } else {
            instantiation = data
            .then(response => response.arrayBuffer())
            .then(buffer => WebAssembly.instantiate(buffer, imports));
        }
    }
    return instantiation.then(({instance}) => {
        wasm = init.wasm = instance.exports;

    });
};
self.wasm_bindgen = Object.assign(init, __exports);
})();
