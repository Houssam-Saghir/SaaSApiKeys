using System.Security.Cryptography;
using System.Text;

namespace SaaS.IdentityServerApi.Services;

public static class ApiKeyHashing
{
    // Hash = HMACSHA256(serverSecret, publicId:secretPart)
    public static string ComputeHash(string serverSecret, string publicId, string secretPart)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(serverSecret));
        var payload = $"{publicId}:{secretPart}";
        var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hashBytes); // uppercase hex
    }

    public static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
}