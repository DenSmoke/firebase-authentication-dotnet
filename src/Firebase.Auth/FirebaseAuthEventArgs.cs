namespace Firebase.Auth
{
    using System;

    public class FirebaseAuthEventArgs : EventArgs
    {
        public readonly FirebaseAuth FirebaseAuth;

        public FirebaseAuthEventArgs(FirebaseAuth auth)
        {
            FirebaseAuth = auth;
        }
    }
}
