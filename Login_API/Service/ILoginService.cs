using System;
using System.Security.Claims;

namespace Login_API.Service;

public interface ILoginService
{
    Task<TokenModel> Login(LoginRequestDTO loginRequestDTO);
    LogonUserModel GetCurrentUser();
    string GenerateAccessToken(ClaimsIdentity claims);
    string GenerateRefreshToken(ClaimsIdentity claims,DateTime ExpiresTime  ));
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);

}