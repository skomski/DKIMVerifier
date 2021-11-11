import Crypto
import Foundation
import _CryptoExtras

func checkRSA_SHA1_Signature(encodedKey: Data, signature: Data, data: Data) throws
  -> Bool {
  let key = try _RSA.Signing.PublicKey.init(derRepresentation: encodedKey)
  let signature = _RSA.Signing.RSASignature.init(rawRepresentation: signature)

  return key.isValidSignature(
    signature, for: Crypto.Insecure.SHA1.hash(data: data),
    padding: _RSA.Signing.Padding.insecurePKCS1v1_5)
}

func checkRSA_SHA256_Signature(encodedKey: Data, signature: Data, data: Data) throws
  -> (Int, Bool) {
  let key = try _RSA.Signing.PublicKey.init(derRepresentation: encodedKey)
  let signature = _RSA.Signing.RSASignature.init(rawRepresentation: signature)

  return (
    key.keySizeInBits,
    key.isValidSignature(
      signature, for: Crypto.SHA256.hash(data: data),
      padding: _RSA.Signing.Padding.insecurePKCS1v1_5)
  )
}

func checkEd25519_SHA256_Signature(encodedKey: Data, signature: Data, data: Data) throws
  -> Bool {
  let key = try Crypto.Curve25519.Signing.PublicKey.init(rawRepresentation: encodedKey)
  return key.isValidSignature(signature, for: Data(Crypto.SHA256.hash(data: data)))
}
