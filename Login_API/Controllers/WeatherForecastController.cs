using Login_API.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

public class AppSetting
{
    public ApiSetting ApiSetting { get; set; }
    public GoogleMapApiKey GoogleMapApiKey {get;set;}
    
}
public class ApiSetting
{
    public string ACSecret { get; set; }
    public string RfSecret { get; set; }
}
public class GoogleMapApiKey{
    public string Server_LOCAL {get;set;}
}
public class LoginResponseDTO1
{
    public UserDTO User { get; set; }
    public string Role { get; set; }
    public List<string> Roles { get; set; } = new List<string>();
    public string AccessToken { get; set; }
    public bool Success { get; set; }
    public string? Message { get; set; }
    public string RefreshToken { get; internal set; }
}

public class UserDTO
{
    public string ID { get; set; }
    public string UserName { get; set; }
    public string Name { get; set; }
}

namespace Login_API.Controllers
{
    [ApiController]
    [Route("/api/[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;
        private readonly ILoginService loginService;

        public WeatherForecastController(ILogger<WeatherForecastController> logger, ILoginService loginService)
        {
            _logger = logger;
            this.loginService = loginService;
        }
        [Authorize(Roles = "SP")]
        [HttpGet(Name = "GetWeatherForecast")]
        public IEnumerable<WeatherForecast> Get()
        {
            var ccc = HttpContext.User.Claims;

            var tttt = loginService.GetCurrentUser();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [HttpGet("Testt")]
        public async Task<IActionResult> SetSession()
        {
            return Ok("Testt");        
        }
        
    }
}
