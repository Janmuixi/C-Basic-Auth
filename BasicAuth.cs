public class FilterAuth : ActionFilterAttribute
    {
        public override void OnActionExecuting(HttpActionContext filterContext)
        {
            var request = HttpContext.Current.Request;
            var authHeader = request.Headers["Authorization"];

            if (authHeader == null)
            {
                filterContext.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                return;
            }


            var authHeaderVal = AuthenticationHeaderValue.Parse(authHeader);
            if (!authHeaderVal.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase) && authHeaderVal.Parameter == null)
            {
                filterContext.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                return;
            }

            var userVal = WebConfigurationManager.AppSettings["user"].ToString();
            var passwordVal = WebConfigurationManager.AppSettings["password"].ToString();
            var encoding = Encoding.GetEncoding("iso-8859-1");

            int separator = encoding.GetString(Convert.FromBase64String(authHeaderVal.Parameter)).IndexOf(':');
            string name = encoding.GetString(Convert.FromBase64String(authHeaderVal.Parameter)).Substring(0, separator);
            string password = encoding.GetString(Convert.FromBase64String(authHeaderVal.Parameter)).Substring(separator + 1);
            if (name != userVal || password != passwordVal)
                filterContext.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        }
    }
