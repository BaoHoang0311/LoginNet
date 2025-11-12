
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using BasicAuth.API;
using Login_API.Controllers;
using Login_API.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using NRedisStack;
using NRedisStack.RedisStackCommands;
using StackExchange.Redis;

namespace Login_API
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi();
            builder.Services.AddScoped<ILoginService, LoginService>();
            builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            // App App Setting
            builder.Services.AddAppSetting(builder.Configuration);
            builder.Services.AddInitDependencyService();


            builder.Services.AddSwaggerGen(options =>
            {
                #region Basic Authentication
                // options.AddSecurityDefinition("Bao_Basic", new OpenApiSecurityScheme
                // {
                //     Name = "Authorization",
                //     Type = SecuritySchemeType.Http,
                //     Scheme = "Basic",
                //     In = ParameterLocation.Header,
                //     Description = "Basic Authorization header using the Bearer scheme. bao/1234"
                // });
                // options.AddSecurityRequirement(new OpenApiSecurityRequirement
                // {
                //    {
                //          new OpenApiSecurityScheme
                //            {
                //                Reference = new OpenApiReference
                //                {
                //                    Type = ReferenceType.SecurityScheme,
                //                    Id = "Bao_Basic"
                //                }
                //            },
                //            new string[] {}
                //    }
                // });
                #endregion


                #region jwt authentication
                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description =
                        "JWT Authorization header using the Bearer scheme. \r\n\r\n " +
                        "Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\n" +
                        "Example: \"12345abcdef\"",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Scheme = "Bearer"
                });
                options.AddSecurityRequirement(new OpenApiSecurityRequirement()
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = ParameterLocation.Header
                        },
                        new List<string>()
                    }
                });
                #endregion
            });

            // #region Basic Authentication
            // builder.Services.AddAuthentication("Bao_Basic")
            //    .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("Bao_Basic",null);

            /** Gọi HttpClient khi dùng Basic Auth
                var client = new HttpClient();
                var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:5001/api/WeatherForecast");

                var authenticationString = $"bao:1234";
                var base64EncodedAuthenticationString = Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(authenticationString));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", base64EncodedAuthenticationString);
                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();
                Console.WriteLine(await response.Content.ReadAsStringAsync());
            */
            // #endregion


            #region  jwt

            var key = builder.Configuration.GetValue<string>("AppSetting:ApiSetting:ACSecret");

            builder.Services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(x =>
            {
                x.SaveToken = true;
                x.RequireHttpsMetadata = false;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key)),

                    ValidateIssuer = false, // phát hành ValidIssuer = "https://localhost:5001",
                    ValidateAudience = false,

                    ValidateLifetime = true,  // Phải bật lên
                    ClockSkew = TimeSpan.Zero // Loại bỏ khoảng trễ mặc định
                };
                // ✅ Hook vào sự kiện
                x.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var redisConn = context.HttpContext.RequestServices.GetRequiredService<IConnectionMultiplexer>();
                        var db = redisConn.GetDatabase();
                        var ccc = context.SecurityToken;
                        var sessionId = context.Principal.FindFirst(c => c.Type == "SessionID")?.Value;

                        if (string.IsNullOrEmpty(sessionId))
                        {
                            context.Fail("SessionID claim missing");
                            return;
                        }

                        // Check Redis
                        var tokenRedis = await db.StringGetAsync($"SessionID:UserID:{sessionId}");
                        if (tokenRedis.IsNullOrEmpty == true)
                        {
                            context.Fail("Session invalidated, please login again");
                            return;
                        }
                    },
                    OnAuthenticationFailed = context =>
                    {
                        context.Response.StatusCode = 401;
                        return Task.CompletedTask;
                    }
                };
            });
            #endregion

            builder.Services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect("127.0.0.1:6369"));


            #region  Session
            builder.Services.AddDistributedMemoryCache();
            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });
            #endregion
            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();

            }
            app.UseSwagger();
            app.UseSwaggerUI();
            app.UseSession();
            app.UseHttpsRedirection();
            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
public static class InstallerExtensions
{
    public static void AddInitDependencyService(this IServiceCollection services)
    {
        DependencyInjectionHelper.Init(ref services);
    }
    public static void AddAppSetting(this IServiceCollection services, IConfiguration configuration)
    {

        //C3    
        services.Configure<AppSetting>(configuration.GetSection("AppSetting"));


        services.AddScoped<ILoginService, LoginService>();
    }
}