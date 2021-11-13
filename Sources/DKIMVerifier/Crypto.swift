import Crypto
import Foundation
import _CryptoExtras

func checkRSA_SHA256_Signature(encodedKey: Data, signature: Data, data: Data) throws
  -> (Int, Bool)
{
  let key: _RSA.Signing.PublicKey
  do {
    key = try _RSA.Signing.PublicKey.init(derRepresentation: encodedKey)
  } catch {
    throw DKIMError.PublicKeyWithIncorrectParameters(
      message: "_RSA.Signing.PublicKey.init -> \(error)")
  }
  let signature = _RSA.Signing.RSASignature.init(rawRepresentation: signature)

  return (
    key.keySizeInBits,
    key.isValidSignature(
      signature, for: Crypto.SHA256.hash(data: data),
      padding: _RSA.Signing.Padding.insecurePKCS1v1_5)
  )
}

func checkEd25519_SHA256_Signature(encodedKey: Data, signature: Data, data: Data) throws
  -> Bool
{
  let key: Crypto.Curve25519.Signing.PublicKey
  do {
    key = try Crypto.Curve25519.Signing.PublicKey.init(rawRepresentation: encodedKey)
  } catch {
    throw DKIMError.PublicKeyWithIncorrectParameters(
      message: "Crypto.Curve25519.Signing.PublicKey.init -> \(error)")
  }
  return key.isValidSignature(signature, for: Data(Crypto.SHA256.hash(data: data)))
}
