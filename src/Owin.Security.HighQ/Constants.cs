namespace Authentication.Web.OWIN.HighQ
{
    public class Constants
    {
        public const string DefaultAuthenticationType = "HighQ";
        public const string AuthorizationEndpoint = "https://{0}/{1}/authorize.action?response_type=code&client_id={2}&redirect_uri={3}";
        public const string TokenEndpoint = "https://{0}/{1}/api/oauth2/token";
        public const string UserInformationEndpoint = "https://{0}/{1}/api/{2}/users/{3}?type=email";
    }
}