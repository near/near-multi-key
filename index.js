const crypto = require('./crypto')

function compPubKey(pk1, pk2) {
    return crypto.addPublicKeys(pk1, pk2)
}

function multiSign(k1, k2, msg) {
    const compPK = compPubKey(k1.publicKey, k2.publicKey),
        { data, secret } = firstSign(compPK, k2.secretKey, msg),
        sig = secondSign(compPK, k1.secretKey, msg, data, secret)
    return { compPK, sig }
}

function firstSign(compPK, secretKey, msg) {
    const { data, secret } = crypto.multiSignStep1(),
        step2 = crypto.multiSignStep2(data, msg, compPK, secretKey)
    return { data: step2, secret }
}

// data, secret from firstSign
function secondSign(compPK, secretKey, msg, data, secret) {
    return crypto.multiSignStep3(data, secret, msg, compPK, secretKey)
}

module.exports = {
    multiSign,
    firstSign,
    secondSign,
}