// openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -x509 -nodes -days 3650 -out secp384r1_cert.pem -keyout secp384r1_key.pem -subj "/CN=allerate.dev"
// openssl ec -in secp384r1_key.pem -no_public -outform PEM -out secp384r1_private_key.pem
// openssl ec -in secp384r1_key.pem -pubout -outform PEM -out secp384r1_public_key.pem

pub const certicate =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBwDCCAUagAwIBAgIUJeTBZUI9hoSnM97dPHldsr8VrYowCgYIKoZIzj0EAwIw
    \\FzEVMBMGA1UEAwwMYWxsZXJhdGUuZGV2MB4XDTIzMDcyOTA4NTQyM1oXDTMzMDcy
    \\NjA4NTQyM1owFzEVMBMGA1UEAwwMYWxsZXJhdGUuZGV2MHYwEAYHKoZIzj0CAQYF
    \\K4EEACIDYgAEiR2I/fGmU0EFoBu65+dd9ixKXPhAdB93VQGN8GgFQN+tlL2WaGo+
    \\VTN/IP8BfwaMeHNEYCtLm202nOGb+iSuiDe9MixdktXo56PpwvT5oesKM2CUNnQG
    \\vgXquPnlrrqro1MwUTAdBgNVHQ4EFgQUXwoWpkpl9ya/1ndU1wmM3veOkL8wHwYD
    \\VR0jBBgwFoAUXwoWpkpl9ya/1ndU1wmM3veOkL8wDwYDVR0TAQH/BAUwAwEB/zAK
    \\BggqhkjOPQQDAgNoADBlAjEA+ks4AhNLxr6Bqt7EOD2rRIfi4Pxrn56a7NIPJevp
    \\os+n0Qeh5+XjwSdtH0nOfJikAjABsFzq9DqqrqNZYHLum+HE3rEt6dKFdKfrjc27
    \\4ZtVDLg/nRuNcojaHno7HzOh9Sw=
    \\-----END CERTIFICATE-----
;

pub const keys =
    \\-----BEGIN PRIVATE KEY-----
    \\MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB3cN9+nfYfC5Z0AWiK
    \\agWvNEpErsIpKPYWhFN9nWu0XoI7aH46XhFel37936V0l9OhZANiAASJHYj98aZT
    \\QQWgG7rn5132LEpc+EB0H3dVAY3waAVA362UvZZoaj5VM38g/wF/Box4c0RgK0ub
    \\bTac4Zv6JK6IN70yLF2S1ejno+nC9Pmh6wozYJQ2dAa+Beq4+eWuuqs=
    \\-----END PRIVATE KEY-----
;

pub const private_key =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MD4CAQEEMHdw336d9h8LlnQBaIpqBa80SkSuwiko9haEU32da7RegjtofjpeEV6X
    \\fv3fpXSX06AHBgUrgQQAIg==
    \\-----END EC PRIVATE KEY-----
;

pub const public_key =
    \\-----BEGIN PUBLIC KEY-----
    \\MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEiR2I/fGmU0EFoBu65+dd9ixKXPhAdB93
    \\VQGN8GgFQN+tlL2WaGo+VTN/IP8BfwaMeHNEYCtLm202nOGb+iSuiDe9MixdktXo
    \\56PpwvT5oesKM2CUNnQGvgXquPnlrrqr
    \\-----END PUBLIC KEY-----
;
