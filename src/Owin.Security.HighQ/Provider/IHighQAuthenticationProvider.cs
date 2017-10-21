using System.Threading.Tasks;

namespace Authentication.Web.OWIN.HighQ.Provider
{
    public interface IHighQAuthenticationProvider
    {
        Task Authenticated(HighQAuthenticatedContext context);
        Task ReturnEndpoint(HighQReturnEndpointContext context);
        void ApplyRedirect(HighQApplyRedirectContext context);
    }
}