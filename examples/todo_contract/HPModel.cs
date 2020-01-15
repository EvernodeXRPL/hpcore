using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace HotPocket
{
    public class ContractArgs
    {
        [JsonProperty("version")]
        public string Version { get; set; }

        [JsonProperty("pubkey")]
        public string PubKey { get; set; }

        [JsonProperty("ts")]
        public string Timestamp { get; set; }

        [JsonProperty("hpfd")]
        public IOPipe HotPocketPipe { get; set; }

        [JsonProperty("nplfd")]
        public IOPipe NplPipe { get; set; }

        [JsonProperty("usrfd")]
        public Dictionary<string, IOPipe> UserPipes { get; set; }

        [JsonProperty("unl")]
        public string[] Unl { get; set; }
    }

    [JsonConverter(typeof(IOPipeJsonConverter))]
    public class IOPipe
    {
        public int ReadFD { get; set; }
        public int WriteFD { get; set; }
    }

    public class IOPipeJsonConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(IOPipe);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null)
                return null;
            var array = JArray.Load(reader);
            var pipe = (existingValue as IOPipe ?? new IOPipe());
            pipe.ReadFD = (int)array.ElementAtOrDefault(0);
            pipe.WriteFD = (int)array.ElementAtOrDefault(1);
            return pipe;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var pipe = (IOPipe)value;
            serializer.Serialize(writer, new[] { pipe.ReadFD, pipe.WriteFD });
        }
    }
}