using System;

namespace Firebase.Auth
{
    public class FirebaseAuthException : Exception
    {
        public FirebaseAuthException(string requestUrl, string requestData, string responseData, Exception innerException, AuthErrorReason reason = AuthErrorReason.Undefined)
            : base(GenerateExceptionMessage(requestUrl, requestData, responseData, reason), innerException)
        {
            RequestUrl = requestUrl;
            RequestData = requestData;
            ResponseData = responseData;
            Reason = reason;
        }

        /// <summary>
        /// Post data passed to the authentication service.
        /// </summary>
        public string RequestData { get; }

        public string RequestUrl { get; }

        /// <summary>
        /// Response from the authentication service.
        /// </summary>
        public string ResponseData { get; }

        /// <summary>
        /// indicates why a login failed. If not resolved, defaults to
        /// <see cref="AuthErrorReason.Undefined"/>.
        /// </summary>
        public AuthErrorReason Reason { get; }

        private static string GenerateExceptionMessage(string requestUrl, string requestData, string responseData, AuthErrorReason errorReason) => $"Exception occured while authenticating.\nUrl: {requestUrl}\nRequest Data: {requestData}\nResponse: {responseData}\nReason: {errorReason}";

        public FirebaseAuthException()
        {
        }

        public FirebaseAuthException(string message) : base(message)
        {
        }

        public FirebaseAuthException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
