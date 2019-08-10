namespace Firebase.Auth
{
    using System;
    using System.Linq;
    using System.Reflection;
    using System.Runtime.Serialization;

    public static class EnumExtensions
    {
        public static string ToEnumString<T>(this T type) where T : struct, IConvertible
        {
            var enumType = typeof(T);
            var name = Enum.GetName(enumType, type);
            var enumMemberAttribute = ((EnumMemberAttribute[])enumType.GetTypeInfo().DeclaredFields.First(f => f.Name == name).GetCustomAttributes(typeof(EnumMemberAttribute), true)).Single();

            return enumMemberAttribute.Value;
        }
    }
}
