/* tslint:disable */
export class Ecc {
free(): void;

static  from_seed(arg0: string): Ecc;

static  from_buffer(arg0: Uint8Array): Ecc;

 to_wif(): string;

 to_public_str(arg0: string): string;

 sign_hex(arg0: string): string;

 sign_buffer(arg0: Uint8Array): Uint8Array;

 sign_buffer_to_hex(arg0: Uint8Array): string;

 decode_memo(arg0: string, arg1: BigInt, arg2: string): string;

}
