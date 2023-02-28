namespace LabWork22;

public class Data
{
    public Data(string siteApp, string login, string password)
    {
        SiteApp = siteApp;
        Login = login;
        Password = password;
    }

    public string SiteApp { get; }
    public string Login { get; }
    public string Password { get; }
}