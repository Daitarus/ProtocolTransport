using CryptL;

namespace ProtocolTransport
{
    internal class SessionIdCom
    {
        private int lengthSessionId = HashSHA256.Length;

        public readonly byte[] sessionId;
        public readonly TypeComAuth type;

        public SessionIdCom(byte[] sessionId)
        {
            if (sessionId == null)
                throw new ArgumentNullException(nameof(sessionId));
            if (sessionId.Length != lengthSessionId)
                throw new ArgumentException($"{nameof(sessionId)} size must be {lengthSessionId}");

            type = TypeComAuth.SESSION_ID;
            this.sessionId = sessionId;
        }

        public byte[] ConvertToBytes()
        {

            byte[] bytes = new byte[sessionId.Length + 1];

            bytes[0] = (byte)type;

            Array.Copy(sessionId, 0, bytes, 1, sessionId.Length);

            return bytes;
        }

        public static bool ParseToCom(byte[] buffer, out SessionIdCom? sessionIdCom)
        {
            if (buffer == null || buffer.Length == 0)
                throw new ArgumentNullException(nameof(buffer));

            TypeComAuth typeData;
            byte[] payLoad = new byte[buffer.Length - 1];

            try
            {
                typeData = (TypeComAuth)buffer[0];
            }
            catch
            {
                throw new ArgumentOutOfRangeException(nameof(typeData));
            }
            if (typeData == TypeComAuth.SESSION_ID)
            {
                Array.Copy(buffer, 1, payLoad, 0, buffer.Length - 1);
                sessionIdCom = new SessionIdCom(payLoad);
                return true;
            }
            else
            {
                sessionIdCom = null;
                return false;
            }
        }
    }
}
