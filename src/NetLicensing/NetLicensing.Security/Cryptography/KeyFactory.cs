using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetLicensing.Security.Cryptography
{
    public static class KeyFactory
    {
        /// <summary>
        /// Encrypts and encodes the private key.
        /// </summary>
        /// <param name="key">The private key.</param>
        /// <param name="passPhrase">The pass phrase to encrypt the private key.</param>
        /// <returns>The encrypted private key.</returns>
        public static string ToEncryptedPrivateKeyString(AsymmetricKeyParameter key, string passPhrase)
        {
            return BouncyCastle.KeyFactory.ToEncryptedPrivateKeyString(key, passPhrase);
        }

        /// <summary>
        /// Decrypts the provided private key.
        /// </summary>
        /// <param name="privateKey">The encrypted private key.</param>
        /// <param name="passPhrase">The pass phrase to decrypt the private key.</param>
        /// <returns>The private key.</returns>
        public static string ToEncryptedPrivateKeyString(string key, string passPhrase)
        {
            return null;
        }



    }
}
