
using Microsoft.Extensions.Options;

public class PortalSettingHelper
{
    // public static AppSetting AppSetting => DependencyInjectionHelper.GetService<IOptions<AppSetting>>()?.Value ?? throw new Exception("Please check environment variable in appsetting.json");


    #region Database Settings
    public static AppSetting GetAppSetting()
    {
        return DependencyInjectionHelper.GetService<IOptions<AppSetting>>()?.Value;
    }

    #endregion
}
