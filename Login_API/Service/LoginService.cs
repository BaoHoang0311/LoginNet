using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using StackExchange.Redis;

namespace Login_API.Service;

public class LogonUserModel
{
    public Guid Key { get; set; }
    public long UserId { get; set; }
    public string Username { get; set; }
    public string DisplayName { get; set; }
    public string RoleID { get; set; }
    public int CityID { get; set; }
    public int CountryID { get; set; }
    public string RoleName { get; set; }
    public List<string> LstRoleName { get; set; }
    public string Email { get; set; }
    public string Name { get; internal set; }
    public string LoginType { get; internal set; }
    public string ID { get; internal set; }
}
public class LoginService : ILoginService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly LogonUserModel _userModel;
    private readonly IDatabase _redis;

    public LoginService(IHttpContextAccessor httpContextAccessor, IConnectionMultiplexer redis)
    {
        _httpContextAccessor = httpContextAccessor;
        _redis = redis.GetDatabase();
    }


    public LogonUserModel GetCurrentUser()
    {
        if (_httpContextAccessor.HttpContext != null)
        {
            var user = _httpContextAccessor.HttpContext.User;
            if (user != null && user.Claims.Count() > 0)
            {
                var result = new LogonUserModel();
                result.Name = user.FindFirst(ClaimTypes.Name).Value;
                result.ID = user.Claims.FirstOrDefault(k => k.Type.ToString().Equals("RoleID")).Value.ToString();
                result.LoginType = user.Claims.FirstOrDefault(k => k.Type.ToString().Equals("LoginType")).Value.ToString();
                result.RoleID = user.Claims.FirstOrDefault(k => k.Type.ToString().Equals("RoleID")).Value.ToString();
                result.LstRoleName = user.FindAll(ClaimTypes.Role).Select(x => x.Value).ToList();
                return result;
            }
            return new LogonUserModel();
        }
        return new LogonUserModel();
    }


    public async Task<TokenModel> Login(LoginRequestDTO loginRequestDTO)
    {
        try
        {
            var Server_LOCAL = PortalSettingHelper.GetAppSetting().GoogleMapApiKey.Server_LOCAL;

            var data1 = loginRequestDTO.UserName == "bao" && loginRequestDTO.Password == "1234";

            #region CreateToken
            var guidnew = Guid.CreateVersion7().ToString();
            ClaimsIdentity claimIdentity = new ClaimsIdentity(new List<Claim>()
            {
                new Claim(ClaimTypes.Name,"bao"),
                new Claim("RoleID","1"),
                new Claim("SessionID", guidnew),
                new Claim("hihi","Bao go hi hi"),
                new Claim("FullNameCuaMinh","Nguyen_Le_Hoang_Bao"),
                new Claim("InternalID",Guid.CreateVersion7().ToString())
            });
            #endregion
            foreach (var role in new List<string>() { "Admin", "SP" })
            {
                claimIdentity.AddClaim(new Claim(ClaimTypes.Role, role));
            }

            var tokenRedis = await _redis.StringSetAsync($"SessionID:UserID:{guidnew}", "active",TimeSpan.FromDays(5));

            var loginResponseDTO1 = new TokenModel()
            {
                AccessToken = GenerateAccessToken(claimIdentity),
                RefreshToken = GenerateRefreshToken(claimIdentity, DateTime.UtcNow.AddDays(5) )
            };
            return loginResponseDTO1;
        }
        catch (Exception ex)
        {
            return new TokenModel()
            {
                AccessToken = string.Empty,
                RefreshToken = string.Empty
            };
        }
    }
    // Write token
    public string GenerateAccessToken(ClaimsIdentity claims)
    {
        claims.AddClaim(new Claim("LoginType", "Access Token"));
        var secretkey = PortalSettingHelper.GetAppSetting().ApiSetting.ACSecret;
        var key = Encoding.ASCII.GetBytes(secretkey);

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDes = new SecurityTokenDescriptor
        {
            Subject = claims,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = "https://localhost:5001", // 👈 phải khớp
            SigningCredentials = new(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
        };

        var CreateToken = tokenHandler.CreateToken(tokenDes);
        var token = tokenHandler.WriteToken(CreateToken);
        return token;
    }

    public string GenerateRefreshToken(ClaimsIdentity claims,DateTime ExpiresTime  )
    {
        claims.AddClaim(new Claim("LoginType", "Refresh Token"));
        var rfKey = PortalSettingHelper.GetAppSetting().ApiSetting.RfSecret;
        var key = Encoding.ASCII.GetBytes(rfKey);
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDes = new SecurityTokenDescriptor
        {
            Subject = claims,
            Expires = ExpiresTime,
            Issuer = "https://localhost:5001", // 👈 phải khớp
            SigningCredentials = new(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
        };
        var CreateRfToken = tokenHandler.CreateToken(tokenDes);
        var rftoken = tokenHandler.WriteToken(CreateRfToken);
        return rftoken;
    }

    public ClaimsPrincipal GetPrincipalFromExpiredToken(string rfToken)
    {
        try
        {
            var secretkey = PortalSettingHelper.GetAppSetting().ApiSetting.RfSecret;

            var key = Encoding.ASCII.GetBytes(secretkey);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case


                #region Validate Issuer
                // ValidateIssuer = true,
                // Issuer: https://localhost:5002 ,(lỗi IDX10211: Unable to validate issuer. The 'issuer' parameter is null or whitespace.hjihiuiii)
                // ValidIssuer = "https://localhost:5002" ,
                #endregion

                ValidateIssuer = true,
                ValidIssuer = "https://localhost:5001",

                // Quăng exception IDX10223: Lifetime validation failed. The token is expired. ValidTo (UTC): '07-04-2025 15:20:09', Current time (UTC): '07-04-2025 15:20:35'.hjihiuiii
                ValidateLifetime = true, //here we are saying that we don't care about the token's expiration date
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;

            var Claimprincipal = tokenHandler.ValidateToken(rfToken, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");
            return Claimprincipal;
        }
        catch (Exception ex)
        {
            throw new(ex.Message + "hjihiuiii");
        }
    }
}
