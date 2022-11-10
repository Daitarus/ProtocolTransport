using CryptL;

namespace ProtocolTransport
{
    internal class RsaPkeyCom
    {
        public readonly byte[] publicKey;
        public readonly TypeComAuth type;
        public RsaPkeyCom(byte[] publicKey)
        {
            type = TypeComAuth.RSAPKEY;

            CryptRSA.CheckExeptionKey(publicKey, false);

            this.publicKey = publicKey;
        }

        public byte[] ConvertToBytes()
        {

            byte[] bytes = new byte[publicKey.Length + 1];

            bytes[0] = (byte)type;

            Array.Copy(publicKey, 0, bytes, 1, publicKey.Length);

            return bytes;
        }

        public static bool ParseToCom(byte[] buffer, out RsaPkeyCom? rsaPkeyCom)
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
            if (typeData == TypeComAuth.RSAPKEY)
            {
                Array.Copy(buffer, 1, payLoad, 0, buffer.Length - 1);
                rsaPkeyCom = new RsaPkeyCom(payLoad);
                return true;
            }
            else
            {
                rsaPkeyCom = null;
                return false;
            }
        }
    }
}
