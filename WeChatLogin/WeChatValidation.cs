using System;
using System.Text;
using System.Security.Cryptography;

namespace WeChatLogin
{
    public class WeChatValidation
    {
        public static bool CheckSignature(string token, string signature, string timestamp, string nonce)
        {
            string[] tokenArr = { token, timestamp, nonce };

            Array.Sort(tokenArr);

            var tokenStr = string.Join("", tokenArr);

            var sha1CryptoServiceProvider = new SHA1CryptoServiceProvider();

            sha1CryptoServiceProvider.ComputeHash(Encoding.Default.GetBytes(tokenStr));

            var tokenHashHexStr = BitConverter.ToString(sha1CryptoServiceProvider.Hash).Replace("-", string.Empty).ToLower();

            return tokenHashHexStr.Equals(signature);
        }
    }
}
