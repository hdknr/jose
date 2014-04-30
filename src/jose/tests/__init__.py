# -*- coding: utf-8 -*-

from jose.utils import base64

_S = lambda o: ''.join([chr(i) for i in o])
_BE = lambda s: base64.base64url_encode(s)
_BD = lambda s: base64.base64url_decode(s)


class JWS_A1:
    jws_oct = [
        123, 34, 116, 121, 112, 34, 58,
        34, 74, 87, 84, 34, 44, 13, 10, 32,
        34, 97, 108, 103, 34, 58, 34,
        72, 83, 50, 53, 54, 34, 125]
    jws_b64 = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'

    payload_oct = [
        123, 34, 105, 115, 115, 34, 58,
        34, 106, 111, 101, 34, 44, 13, 10,
        32, 34, 101, 120, 112, 34, 58, 49,
        51, 48, 48, 56, 49, 57, 51, 56,
        48, 44, 13, 10, 32, 34, 104, 116,
        116, 112, 58, 47, 47, 101, 120, 97,
        109, 112, 108, 101, 46, 99, 111, 109,
        47, 105, 115, 95, 114, 111,
        111, 116, 34, 58, 116, 114, 117, 101, 125]

    payload_b64 = ''.join([
        'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA',
        '4MTkzODAsDQogImh0dHA6Ly9leGFt',
        'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'])

    sinput_oct = [
        101, 121, 74, 48, 101, 88, 65,
        105, 79, 105, 74, 75, 86, 49, 81,
        105, 76, 65, 48, 75, 73, 67, 74,
        104, 98, 71, 99, 105, 79, 105, 74,
        73, 85, 122, 73, 49, 78, 105, 74,
        57, 46, 101, 121, 74, 112, 99, 51,
        77, 105, 79, 105, 74, 113, 98, 50,
        85, 105, 76, 65, 48, 75, 73, 67,
        74, 108, 101, 72, 65, 105, 79, 106,
        69, 122, 77, 68, 65, 52, 77, 84,
        107, 122, 79, 68, 65, 115, 68, 81,
        111, 103, 73, 109, 104, 48, 100,
        72, 65, 54, 76, 121, 57, 108, 101,
        71, 70, 116, 99, 71, 120, 108, 76,
        109, 78, 118, 98, 83, 57, 112, 99,
        49, 57, 121, 98, 50, 57, 48, 73,
        106, 112, 48, 99, 110, 86, 108, 102, 81]

    jwk_dict = {
        "kty": "oct",
        "k": "".join([
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75",
            "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"])
    }
    sig_b64 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    token = ''.join([
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
        ".",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        ".",
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    ])


class JWS_A2:
    header_oct = [
        123, 34, 97, 108, 103, 34, 58,
        34, 82, 83, 50, 53, 54, 34, 125]
    header_json = '{"alg":"RS256"}'
    header_b64u = 'eyJhbGciOiJSUzI1NiJ9'

    payload_b64u = ''.join([
        'eyJpc3MiOiJqb2UiLA0KICJleHAiOj',
        'EzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt',
        'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'])

    s_input_oct = [
        101, 121, 74, 104, 98, 71, 99,
        105, 79, 105, 74, 83, 85, 122, 73,
        49, 78, 105, 74, 57, 46, 101, 121,
        74, 112, 99, 51, 77, 105, 79, 105,
        74, 113, 98, 50, 85, 105, 76, 65,
        48, 75, 73, 67, 74, 108, 101, 72,
        65, 105, 79, 106, 69, 122, 77, 68,
        65, 52, 77, 84, 107, 122, 79, 68,
        65, 115, 68, 81, 111, 103, 73, 109,
        104, 48, 100, 72, 65, 54, 76,
        121, 57, 108, 101, 71, 70, 116, 99,
        71, 120, 108, 76, 109, 78, 118,
        98, 83, 57, 112, 99, 49, 57, 121, 98,
        50, 57, 48, 73, 106, 112, 48,
        99, 110, 86, 108, 102, 81]

    jwk_dict = {
        "kty": "RSA",
        "n": "".join([
            "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx",
            "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs",
            "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH",
            "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV",
            "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8",
            "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"]),
        "e": "AQAB",
        "d": "".join([
            "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I",
            "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0",
            "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn",
            "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT",
            "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh",
            "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"]),
    }

    sig_oct = [
        112, 46, 33, 137, 67, 232, 143,
        209, 30, 181, 216, 45, 191, 120, 69,
        243, 65, 6, 174, 27, 129, 255, 247,
        115, 17, 22, 173, 209, 113, 125,
        131, 101, 109, 66, 10, 253, 60,
        150, 238, 221, 115, 162, 102, 62, 81,
        102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16, 115, 249, 69,
        229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219,
        61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7,
        16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31,
        190, 127, 249, 217, 46, 10, 231,
        111, 36, 242, 91, 51, 187, 230, 244,
        74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 1,
        48, 121, 91, 212, 189, 59, 65, 238,
        202, 208, 102, 171, 101, 25, 129,
        253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239,
        177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202,
        173, 21, 145, 18, 115, 160, 95, 35,
        185, 232, 56, 250, 175, 132, 157,
        105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69,
        34, 165, 68, 200, 242, 122, 122, 45,
        184, 6, 99, 209, 108, 247, 202,
        234, 86, 222, 64, 92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90,
        193, 167, 72, 160, 112, 223, 200,
        163, 42, 70, 149, 67, 208, 25, 238, 251, 71]

    sig_b64u = "".join([
        'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7',
        'AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4',
        'BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K',
        '0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv',
        'hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB',
        'p0igcN_IoypGlUPQGe77Rw'])

    token = "".join([
        "eyJhbGciOiJSUzI1NiJ9",
        ".",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        ".",
        "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7",
        "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4",
        "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K",
        "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv",
        "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB",
        "p0igcN_IoypGlUPQGe77Rw",
    ])


class JWS_A4:
    header_b64 = 'eyJhbGciOiJFUzUxMiJ9'
    payload_b64 = "UGF5bG9hZA"
    signature_b64 = ''.join([
        'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq',
        'wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp',
        'EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn',
    ])

    jwk_dict = {
        "kty": "EC",
        "crv": "P-521",
        "x": "".join([
            "AekpBQ8ST8a8VcfVOTNl353vSrDCLL",
            "JXmPk06wTjxrrjcBpXp5EOnYG_NjFZ",
            "6OvLFV1jSfS9tsz4qUxcWceqwQGk",
        ]),
        "y": "".join([
            "ADSmRA43Z1DSNx_RvcLI87cdL07l6j",
            "QyyBXMoxVg_l2Th-x3S1WDhjDly79a",
            "jL4Kkd0AZMaZmh9ubmf63e3kyMj2",
        ]),
        "d": "".join([
            "AY5pb7A0UFiB3RELSD64fTLOSV_jaz",
            "dF7fLYyuTw8lOfRhWg6Y6rUrPAxerE",
            "zgdRhajnu0ferB0d53vM9mE15j2C"
        ])
    }

    R = [
        1, 220, 12, 129, 231, 171, 194, 209, 232, 135, 233,
        117, 247, 105, 122, 210, 26, 125, 192, 1, 217, 21, 82,
        91, 45, 240, 255, 83, 19, 34, 239, 71, 48, 157, 147,
        152, 105, 18, 53, 108, 163, 214, 68, 231, 62, 153, 150,
        106, 194, 164, 246, 72, 143, 138, 24, 50, 129, 223, 133,
        206, 209, 172, 63, 237, 119, 109]

    S = [
        0, 111, 6, 105, 44, 5, 41, 208, 128, 61, 152, 40, 92,
        61, 152, 4, 150, 66, 60, 69, 247, 196, 170, 81, 193,
        199, 78, 59, 194, 169, 16, 124, 9, 143, 42, 142, 131,
        48, 206, 238, 34, 175, 83, 203, 220, 159, 3, 107, 155,
        22, 27, 73, 111, 68, 68, 21, 238, 144, 229, 232, 148,
        188, 222, 59, 242, 103]


class JWE_A2:
    plaint_oct = [
        76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
        112, 114, 111, 115, 112, 101, 114, 46]
    plaint = _S(plaint_oct)
    jwe_header = '{"alg":"RSA1_5","enc":"A128CBC-HS256"}'
    jwe_header_b64u = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0'
    cek_oct = [
        4, 211, 31, 197, 84, 157, 252, 254, 11,
        100, 157, 250, 63, 170, 106,
        206, 107, 124, 212, 45, 111, 107, 9, 219,
        200, 177, 0, 240, 143, 156, 44, 207]
    cek = _S(cek_oct)
    jwk_dict = dict(
        kty="RSA",
        n="".join([
            "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl",
            "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre",
            "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_",
            "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI",
            "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU",
            "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
        ]),
        e="AQAB",
        d="".join([
            "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq",
            "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry",
            "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_",
            "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj",
            "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj",
            "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
        ])
    )
    jwe_enc_key_oct = [
        80, 104, 72, 58, 11, 130, 236, 139, 132, 189, 255, 205, 61, 86, 151,
        176, 99, 40, 44, 233, 176, 189, 205, 70, 202, 169, 72, 40, 226, 181,
        156, 223, 120, 156, 115, 232, 150, 209, 145, 133, 104, 112, 237, 156,
        116, 250, 65, 102, 212, 210, 103, 240, 177, 61, 93, 40, 71, 231, 223,
        226, 240, 157, 15, 31, 150, 89, 200, 215, 198, 203, 108, 70, 117, 66,
        212, 238, 193, 205, 23, 161, 169, 218, 243, 203, 128, 214, 127, 253,
        215, 139, 43, 17, 135, 103, 179, 220, 28, 2, 212, 206, 131, 158, 128,
        66, 62, 240, 78, 186, 141, 125, 132, 227, 60, 137, 43, 31, 152, 199,
        54, 72, 34, 212, 115, 11, 152, 101, 70, 42, 219, 233, 142, 66, 151,
        250, 126, 146, 141, 216, 190, 73, 50, 177, 146, 5, 52, 247, 28, 197,
        21, 59, 170, 247, 181, 89, 131, 241, 169, 182, 246, 99, 15, 36, 102,
        166, 182, 172, 197, 136, 230, 120, 60, 58, 219, 243, 149, 94, 222,
        150, 154, 194, 110, 227, 225, 112, 39, 89, 233, 112, 207, 211, 241,
        124, 174, 69, 221, 179, 107, 196, 225, 127, 167, 112, 226, 12, 242,
        16, 24, 28, 120, 182, 244, 213, 244, 153, 194, 162, 69, 160, 244,
        248, 63, 165, 141, 4, 207, 249, 193, 79, 131, 0, 169, 233, 127, 167,
        101, 151, 125, 56, 112, 111, 248, 29, 232, 90, 29, 147, 110, 169,
        146, 114, 165, 204, 71, 136, 41, 252]
    jwe_enc_key = _S(jwe_enc_key_oct)
    jwe_enc_key_b64u = ''.join([
        "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm",
        "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc",
        "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF",
        "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8",
        "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv",
        "-B3oWh2TbqmScqXMR4gp_A",
    ])
    iv_oct = [
        3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]
    iv = _S(iv_oct)
    iv_b64u = 'AxY8DCtDaGlsbGljb3RoZQ'
    jwe_protected_header_oct = [
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
        120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
        74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
        50, 73, 110, 48]
    ciphert_oct = [
        40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
        75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
        112, 56, 102]
    ciphert = _S(ciphert_oct)
    ciphert_b64u = 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY'
    auth_tag_oct = [
        246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100,
        191]
    auth_tag = _S(auth_tag_oct)
    auth_tag_b64u = '9hH0vgRfYgPnAHOd8stkvw'
    jwe_token = ''.join([
        "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.",
        "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm",
        "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc",
        "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF",
        "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8",
        "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv",
        "-B3oWh2TbqmScqXMR4gp_A.",
        "AxY8DCtDaGlsbGljb3RoZQ.",
        "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.",
        "9hH0vgRfYgPnAHOd8stkvw",
    ])


class JWE_A3:
    plaint_oct = [
        76, 105, 118, 101, 32, 108,
        111, 110, 103, 32, 97, 110, 100, 32,
        112, 114, 111, 115, 112, 101, 114, 46]
    plaint = _S(plaint_oct)

    iv_oct = [
        3, 22, 60, 12, 43, 67, 104, 105,
        108, 108, 105, 99, 111, 116, 104, 101]
    iv = _S(iv_oct)
    iv_b64 = _BE(iv)


class JWE_B:
    cek_oct = [
        4, 211, 31, 197, 84, 157, 252, 254,
        11, 100, 157, 250, 63, 170, 106,
        206, 107, 124, 212, 45, 111, 107, 9,
        219, 200, 177, 0, 240, 143, 156,
        44, 207]
    cek = _S(cek_oct)


class JWT_A1:
    token = "".join([
        "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.",
        "QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM",
        "oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG",
        "TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima",
        "sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52",
        "YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a",
        "1rZgN5TiysnmzTROF869lQ.",
        "AxY8DCtDaGlsbGljb3RoZQ.",
        "MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM",
        "HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8.",
        "fiK51VwhsxJ-siBMR-YFiA",
    ])


class JWT_A2:
    nested_token = "".join([
        "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU",
        "In0.",
        "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M",
        "qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE",
        "b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh",
        "DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D",
        "YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq",
        "JGTO_z3Wfo5zsqwkxruxwA.",
        "UmVkbW9uZCBXQSA5ODA1Mg.",
        "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB",
        "BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT",
        "-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10",
        "l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY",
        "Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr",
        "ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2",
        "8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE",
        "l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U",
        "zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd",
        "_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ.",
        "AVO9iT5AV4CzvDJCdhSFlQ",
    ])

if __name__ == '__main__':
    import unittest
    import importlib

    for name in ['store', 'utils', 'jwk', 'jws', 'jwe', 'jwt', 'crypto', ]:
        mod = importlib.import_module("test_{:s}".format(name))
        for attr in dir(mod):
            if not attr.startswith('Test'):
                continue
            globals()[attr] = getattr(mod, attr)

    unittest.main()
