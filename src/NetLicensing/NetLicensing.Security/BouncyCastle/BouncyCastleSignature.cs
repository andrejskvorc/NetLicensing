//
// Copyright © 2022 Andrej Skvorc     http://www.skvorc.eu
//
// Author:
//  Andrej Skvorc       <andrej@skvorc.eu>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace NetLicensing.Security.BouncyCastle
{
    public static class BouncyCastleSignature
    {
        private static readonly string signatureAlgorithm = X9ObjectIdentifiers.ECDsaWithSha512.Id;

        /// <summary>
        /// Determines whether the <see cref="License.Signature"/> property verifies for the specified key.
        /// </summary>
        /// <param name="publicKey">The public key in xml string format to verify the <see cref="License.Signature"/>.</param>
        /// <param name="xmlData">The XElemet that contains data to verify signature</param>
        /// <returns>true if the <see cref="License.Signature"/> verifies; otherwise false.</returns>
        public static bool VerifySignature(string publicKey, XElement xmlData)
        {
            var signTag = xmlData.Element("Signature");

            if (signTag == null)
                return false;

            try
            {
                signTag.Remove();

                var pubKey = KeyFactory.FromPublicKeyString(publicKey);

                var documentToSign = Encoding.UTF8.GetBytes(xmlData.ToString(SaveOptions.DisableFormatting));
                var signer = SignerUtilities.GetSigner(signatureAlgorithm);
                signer.Init(false, pubKey);
                signer.BlockUpdate(documentToSign, 0, documentToSign.Length);

                return signer.VerifySignature(Convert.FromBase64String(signTag.Value));
            }
            finally
            {
                xmlData.Add(signTag);
            }
        }

        /// <summary>
        /// Compute a signature and sign this <see cref="License"/> with the provided key.
        /// </summary>
        /// <param name="privateKey">The private key in xml string format to compute the signature.</param>
        /// <param name="passPhrase">The pass phrase to decrypt the private key.</param>
        /// <param name="xmlData">The XElemet that contains data to sign</param>
        public static void Sign(string privateKey, string passPhrase, XElement xmlData)
        {
            var signTag = xmlData.Element("Signature") ?? new XElement("Signature");

            try
            {
                if (signTag.Parent != null)
                    signTag.Remove();

                var privKey = KeyFactory.FromEncryptedPrivateKeyString(privateKey, passPhrase);

                var documentToSign = Encoding.UTF8.GetBytes(xmlData.ToString(SaveOptions.DisableFormatting));
                var signer = SignerUtilities.GetSigner(signatureAlgorithm);
                signer.Init(true, privKey);
                signer.BlockUpdate(documentToSign, 0, documentToSign.Length);
                var signature = signer.GenerateSignature();
                signTag.Value = Convert.ToBase64String(signature);
            }
            finally
            {
                xmlData.Add(signTag);
            }
        }

    }
}
