using CryptL;

namespace ProtocolTransport
{
    internal class AesKeyCom
    {
        public readonly byte[] unionKeyIV;
        public readonly TypeComAuth type;
        public AesKeyCom(byte[] payLoad)
        {
            type = TypeComAuth.AESKEY;

            CryptAES.CheckExeptionUnionKey(payLoad);
            this.unionKeyIV = payLoad;
        }

        public byte[] ConvertToBytes()
        {

            byte[] bytes = new byte[unionKeyIV.Length + 1];

            bytes[0] = (byte)type;

            Array.Copy(unionKeyIV, 0, bytes, 1, unionKeyIV.Length);

            return bytes;
        }

        public static bool ParseToCom(byte[] buffer, out AesKeyCom? aesKeyCom)
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
            if (typeData == TypeComAuth.AESKEY)
            {
                Array.Copy(buffer, 1, payLoad, 0, buffer.Length - 1);
                aesKeyCom = new AesKeyCom(payLoad);
                return true;
            }
            else
            {
                aesKeyCom = null;
                return false;
            }
        }
    }
}
