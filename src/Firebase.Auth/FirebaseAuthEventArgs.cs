using System;

namespace Firebase.Auth
{
    public class FirebaseAuthEventArgs : EventArgs
    {
        public FirebaseAuthEventArgs(FirebaseAuth auth) => FirebaseAuth = auth;

        public FirebaseAuth FirebaseAuth { get; }
    }
}
