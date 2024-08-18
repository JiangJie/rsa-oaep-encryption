import { assert, assertThrows } from '@std/assert';
import { importPublicKey, sha1, sha256, sha384, sha512, type HashAlgorithm } from '../src/mod.ts';

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAix682LW8jwpZEGjFfoom
GvLHCDh8ttPgSB5CBvXZLglimVfVkA7FiGdJqlKkf2kKXqrwSICbgcYUjFHMFdy9
fvUwrKXzFXP46AzzV3ivkam2LB97eDSMI8gaIjumDaIFZAD3E9osYz4LMSI2A0nC
qs+5xZ66JeC/Dtr5W9nobushAhFzZQWS/4I7iSUkV4WFmSG1ACB267z8YZ7YFmlT
1hMFvp+biIsZIx7mebQNqjFjFPP0ZTskXg4UfQt6yyuaPqL55pQ7Wc8iI3umlsSV
hDL1q3+ry7L8VDg7EtDBbodyYT5R62zBuhe7sJrvhtt/R6fZIfISPvRbumwusbf5
XQIDAQAB
-----END PUBLIC KEY-----
`;

const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCLHrzYtbyPClkQ
aMV+iiYa8scIOHy20+BIHkIG9dkuCWKZV9WQDsWIZ0mqUqR/aQpeqvBIgJuBxhSM
UcwV3L1+9TCspfMVc/joDPNXeK+RqbYsH3t4NIwjyBoiO6YNogVkAPcT2ixjPgsx
IjYDScKqz7nFnrol4L8O2vlb2ehu6yECEXNlBZL/gjuJJSRXhYWZIbUAIHbrvPxh
ntgWaVPWEwW+n5uIixkjHuZ5tA2qMWMU8/RlOyReDhR9C3rLK5o+ovnmlDtZzyIj
e6aWxJWEMvWrf6vLsvxUODsS0MFuh3JhPlHrbMG6F7uwmu+G239Hp9kh8hI+9Fu6
bC6xt/ldAgMBAAECggEABMjYQf68FFJM3lowF/Tshbw9mUbcuSqfxHMv86PUZeIs
6desu1vasiEqlijp9IzPrmekGbuR6Dxq+/7F1/xOaGr1KIGQ6DcObif13YIDzcIV
BxRHxN+lGzJC/dQ91tWwkvAlOeGkvv6vrVn/GrgDHH3w5mmZ/s/+2iYF8ev/CQN6
/2t68F7OGx93IwQZnet1L/fDEJbvpKNlc9FOHz9fDeh769RzMxD/QJsiV6zcJuFX
p0EFrQflFQ51sP9jKLpXgK6kKH3ugveQL0fhKHDmNFKUpz9BX2WRZh+3ix1XNk5M
Ppyhg/oeKXvphtubUEZfZRXYBLmACMqVw9ta94n5YQKBgQC/jhESKALWLl7Oc08m
GyQA03z3j3/JNaqXALSRcND38j/mpR+abI9ANDV7njwO8jtrqfXIBTGna9sqOoey
XAnLsvFkB1ndGcz7rcKi6A1CAFcEN7J6E0iePhC1HKqoY7qPMi1HLsyIKctEo20A
J7UNNSylVbUi084Dt6jTo2LPIQKBgQC57KUbHDI557km5RoisVwjyucANDs5oicr
vaSXjDhgvf0b07D5ElhSeJyzLp/LydwasUnYNM/S6az1BFSI5sAtcGiecQ36FXus
UnyWWB1B3bTa/hYPqFAT+QIIRqIqdcg8ARcaoDJgjESDYdG8Yz8N48+Dp98R22Qk
1KU4XolOvQKBgQCP7tPs7JuVDCq4vfQPEf2vkTopWm4OZoDUDfegAUFDzYcua4yf
oErTV2eIh5FhOapkb8T6ksyInIaF6Izl/DpwEPlIzC098ZEQ27OQbQTpPxAjXyaA
i9TY8pHjRLMG7EjWKEHVZtjQx3axEItqvmtQjVAKu6frj3MRYAM/Y1lvgQKBgFk9
1m4x1YXnzP53X1khqqlffguiBn9+brDXIUbAvlrpNrGBpeOXw58qV4TGL1tg8+44
BMrrZonFMgiVYIIpyDrHRuAuQdg1MZygJz7+4mQ4J9Qpu6seTfmYPzp7tOEOkeMD
XvSfyi5/hW9Op552QNDI9VUrYa4vkV0AWKG69ss9AoGAZYuK/nbQv81+AExY2vr7
KaO+FLoszYHNiFbwvjt0e10a2X4wdVrUqiiT4gujrpQEWJigrNjbAmstmjDE1zgW
VxnzlrCOTTZT7/jD4wf53nCQiqRCg2NsIq6/JYOi+tjr6dC8HA8pd58xYAkB+hbZ
wIy0/kd6szCcWK5Ld1kH9R0=
-----END PRIVATE KEY-----
`;

const data = 'rsa-oaep-encryption';

Deno.test('RSA encryption', async () => {
    function byteStringToBuffer(str: string): Uint8Array {
        const { length } = str;
        const u8a = new Uint8Array(length);

        for (let i = 0; i < length; i++) {
            u8a[i] = str.charCodeAt(i);
        }

        return u8a;
    }

    function importDecryptKey(pem: string, sha: string): Promise<CryptoKey> {
        pem = pem.replace(/(-----(BEGIN|END) PRIVATE KEY-----|\s)/g, '');

        const privateKey = byteStringToBuffer(atob(pem));

        return crypto.subtle.importKey(
            'pkcs8',
            privateKey,
            {
                name: 'RSA-OAEP',
                hash: sha,
            },
            false,
            [
                'decrypt',
            ]
        );
    }

    async function decrypt(encryptedData: BufferSource, hash: string) {
        const privateKey = await importDecryptKey(PRIVATE_KEY, hash);
        const decryptedData = new TextDecoder().decode(await crypto.subtle.decrypt(
            {
                name: 'RSA-OAEP',
            },
            privateKey,
            encryptedData
        ));

        return decryptedData;
    }

    assertThrows(() => importPublicKey(PUBLIC_KEY.slice(1)));
    assertThrows(() => importPublicKey(PUBLIC_KEY.replace('+', '')));
    assertThrows(() => importPublicKey(PUBLIC_KEY.replace('M', 'm')));
    assertThrows(() => importPublicKey(PUBLIC_KEY).encrypt(data, {} as unknown as HashAlgorithm));

    async function test() {
        let encryptedData = importPublicKey(PUBLIC_KEY).encrypt(data, sha1.create());
        let decryptedData = await decrypt(encryptedData, 'SHA-1');
        assert(data === decryptedData);

        encryptedData = importPublicKey(PUBLIC_KEY).encrypt(data, sha256.create());
        decryptedData = await decrypt(encryptedData, 'SHA-256');
        assert(data === decryptedData);

        encryptedData = importPublicKey(PUBLIC_KEY).encrypt(data, sha384.create());
        decryptedData = await decrypt(encryptedData, 'SHA-384');
        assert(data === decryptedData);

        encryptedData = importPublicKey(PUBLIC_KEY).encrypt(data, sha512.create());
        decryptedData = await decrypt(encryptedData, 'SHA-512');
        assert(data === decryptedData);
    }

    for (let index = 0; index < 100; index++) {
        await test();
    }
});