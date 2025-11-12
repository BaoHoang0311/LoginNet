using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace BasicAuth.API
{
    public class LoginResponseDTO
    {
        // public LocalUser User { get; set; }
        public string Token { get; set; }
        public bool Success { get; set; }
        public string? Message { get; set; }
    }

    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        #region Property  
        #endregion

        #region Constructor  
        public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }
        #endregion

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                if (!Request.Headers.ContainsKey("Authorization"))
                {
                    // Không có header => cho qua, để Authorization filter xử lý
                    return AuthenticateResult.NoResult();
                }

                var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter)).Split(':');
                var username = credentials.FirstOrDefault();
                var password = credentials.LastOrDefault();

                var data1 = username == "bao" && password == "1234";
                var data = new LoginResponseDTO();

                if (data1 == false)
                {
                    data.Success = false;
                    return AuthenticateResult.Fail($"Authentication failed, Wrong User/Password");

                }
                data.Success = true;

                if (data.Success == false)
                {
                    throw new ArgumentException("Invalid credentials");
                }
                var claims = new[] {
                    new Claim(ClaimTypes.Name, username),
                    new Claim("ID", 1.ToString()),
                    new Claim("LoginType","BasicAuthen"),
                    new Claim("RoleID","12"),
                    new Claim(ClaimTypes.Role,"SP"),
                    new Claim(ClaimTypes.Role,"Admin"),
                };
                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);
                return AuthenticateResult.Success(ticket);
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail($"Authentication failed: {ex.Message}");
            }
        }
    }
}