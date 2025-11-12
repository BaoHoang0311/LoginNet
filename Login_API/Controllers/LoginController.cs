using System.Security.Claims;
using System.Text.Json.Serialization;
using Login_API.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using StackExchange.Redis;
public class LoginRequestDTO
{
    public string? UserName { get; set; } = "bao";
    public string? Password { get; set; } = "1234";
}
namespace Login_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly ILoginService _loginService;
        private readonly IDatabase _db;
        public LoginController(ILoginService loginService, IConnectionMultiplexer connectionMultiplexer)
        {
            _loginService = loginService;
            _db = connectionMultiplexer.GetDatabase();
        }
        [HttpPost("login")]
        [ProducesResponseType(typeof(TokenModel), StatusCodes.Status200OK)]
        public async Task<ActionResult> LogIn(LoginRequestDTO loginRequestDTO)
        {
            try
            {
                var ttt = (await _db.StringGetAsync("abc")).ToString();
                var rnd = new Random();
                var dataSession = new List<object>() { rnd.Next(1, 10), rnd.Next(1, 10), DateTime.Now };
                var zzz1 = JsonConvert.SerializeObject(dataSession);
                HttpContext.Session.SetString("test", zzz1);
                var zzz = PortalSettingHelper.GetAppSetting();

                TokenModel res = await _loginService.Login(loginRequestDTO);
                
                //Add vào database 
                // xxx.refreshToken =  res.refreshToken;
                // xxx.expiryRefreshTokenTime = DateTime.Now.AddDays(7);
                // _context.Add(xxx);
                // await _context.SaveChangeSync();

                return Ok(res);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost("refresh")]
        [ProducesResponseType(typeof(TokenModel), StatusCodes.Status200OK)]
        public async Task<ActionResult> RefreshToken(TokenModel tokenModel)
        {
            try
            {
                // var zzzr = HttpContext.Session.GetString("test");
                // var zzzrDecode = JsonConvert.DeserializeObject<List<object>>(zzzr);

                var claimsPrincipal = _loginService.GetPrincipalFromExpiredToken(tokenModel.RefreshToken);

                var Username = claimsPrincipal.FindAll(x => x.Type == "FullNameCuaMinh").FirstOrDefault().Value;
                var InternalID = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == "InternalID").Value;
                var listRole = claimsPrincipal.FindAll(x => x.Type == ClaimTypes.Role).Select(x => x.Value).ToList();
                var SessionID = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == "SessionID").Value;

                var identity = claimsPrincipal.Identity as ClaimsIdentity;
                var expireTime = DateTime.UtcNow.AddDays(5);
                var sessionID = await _db.StringGetAsync(key: $"SessionID:UserID:{SessionID}");
                if (sessionID.IsNullOrEmpty == true) return BadRequest("Yeu cau dang nhap lai");
                var respone = new TokenModel()
                {
                    AccessToken = _loginService.GenerateAccessToken(identity),
                    // có thể tạo mới hoặc để nguyên rfToken cũ trả về, ExpireTime.AddDays(5) lúc LoginController giữ nguyên
                    RefreshToken = _loginService.GenerateRefreshToken(identity,expireTime),
                };
                return Ok(respone);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost]
        //https://localhost:5001/api/logout
        [Route("/api/logout")]
        public async Task<ActionResult> Logout(TokenModel tokenModel)
        {
            var claimsPrincipal = _loginService.GetPrincipalFromExpiredToken(tokenModel.RefreshToken);
            var SessionID = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == "SessionID").Value;
            var sessionID = await _db.KeyDeleteAsync($"SessionID:UserID:{SessionID}");
            return Ok("Logout thanh cong");
        }
    }
}
