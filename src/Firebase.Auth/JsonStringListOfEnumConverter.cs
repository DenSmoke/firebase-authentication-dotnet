using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Firebase.Auth
{
    internal class JsonStringListOfEnumConverter<T> : JsonConverter<List<T>> where T : struct, IConvertible
    {
        public override List<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartArray)
            {
                throw new JsonException();
            }

            var value = new List<T>();

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndArray)
                {
                    return value;
                }

                if (reader.TokenType != JsonTokenType.String)
                {
                    throw new JsonException();
                }

                var enumType = typeof(T);
                var str = reader.GetString();
                foreach (var name in Enum.GetNames(enumType))
                {
                    var enumMemberAttribute = ((EnumMemberAttribute[])enumType.GetField(name).GetCustomAttributes(typeof(EnumMemberAttribute), true)).Single();
                    if (enumMemberAttribute.Value == str) value.Add((T)Enum.Parse(enumType, name));
                }
            }

            throw new JsonException();
        }

        public override void Write(Utf8JsonWriter writer, List<T> value, JsonSerializerOptions options)
        {
            writer.WriteStartArray();

            var enumType = typeof(T);
            foreach (var item in value)
            {
                var name = Enum.GetName(enumType, item);
                var enumMemberAttribute = ((EnumMemberAttribute[])enumType.GetField(name).GetCustomAttributes(typeof(EnumMemberAttribute), true)).Single();
                writer.WriteStringValue(enumMemberAttribute.Value);
            }

            writer.WriteEndArray();
        }
    }
}
