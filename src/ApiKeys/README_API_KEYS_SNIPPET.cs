// This file is just a placeholder summarizing usage:
//
// 1) Create an API key:
// curl -X POST https://localhost:5001/api-keys -H "X-Demo-User: user-123" -k
//
// Response:
// {
//   "apiKey": "ak_QWERTY12.ABCD1234...",
//   "id": "QWERTY12",
//   "scopes": ["api1"],
//   "expiresUtc": null
// }
//
// 2A) Use API Key directly:
// curl -H "X-Api-Key: ak_QWERTY12.ABCD1234..." https://localhost:5001/data -k
//
// 2B) Exchange API Key for JWT:
// curl -k -X POST https://localhost:5001/connect/token \
//   -H "Content-Type: application/x-www-form-urlencoded" \
//   -d "grant_type=api_key" \
//   -d "api_key=ak_QWERTY12.ABCD1234..." \
//   -d "scope=api1"
//
// Then call protected resource using Bearer token.