using System.Security.Cryptography;
using System.Text;

namespace ApiKeys;

public static class ApiKeyHashing
{
    // Hash = HMACSHA256(ServerSecret, publicId + ":" + secretPart)
    public static string ComputeHash(string serverSecret, string publicId, string secretPart)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(serverSecret));
        var data = $"{publicId}:{secretPart}";
        var bytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToHexString(bytes); // Uppercase hex
    }
}