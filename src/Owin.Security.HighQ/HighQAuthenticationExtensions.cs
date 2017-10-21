using Owin;
using System;

namespace Authentication.Web.OWIN.HighQ
{
    public static class HighQAuthenticationExtensions
    {
        public static IAppBuilder UseHighQAuthentication(this IAppBuilder app, HighQAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(HighQAuthenticationMiddleware), app, options);

            return app;
        }
    }
}