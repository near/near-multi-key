const assert = require('assert') 
const nacl = require('tweetnacl')
const{ multiSign } = require('../index')

it('works', () => {
  let k1 = nacl.sign.keyPair(),
      k2 = nacl.sign.keyPair(),
      msg = nacl.randomBytes(123)
  let { compPK, sig } = multiSign(k1, k2, msg)
  assert(nacl.sign.detached.verify(msg, sig, compPK))
})

it('is not deterministic', () => {
  let k1 = nacl.sign.keyPair(),
      k2 = nacl.sign.keyPair(),
      msg = nacl.randomBytes(123)
  let { k: kk1, sig: sig1 } = multiSign(k1, k2, msg)
  let { k: kk2, sig: sig2 } = multiSign(k1, k2, msg)
  assert.strictEqual(kk1, kk2)
  assert.notDeepStrictEqual(sig1, sig2)
})