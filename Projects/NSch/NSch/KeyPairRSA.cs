/*
Copyright (c) 2002-2016 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright 
     notice, this list of conditions and the following disclaimer in 
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

This code is based on jsch (http://www.jcraft.com/jsch).
All credit should go to the authors of jsch.
*/

using System;
using NSch;
using Sharpen;
using Mono.Math;

namespace NSch
{
    public class KeyPairRSA : NSch.KeyPair
    {
        private byte[] n_array;

        private byte[] pub_array;

        private byte[] prv_array;

        private byte[] p_array;

        private byte[] q_array;

        private byte[] ep_array;

        private byte[] eq_array;

        private byte[] c_array;

        private int key_size = 1024;

        public KeyPairRSA(JSch jsch) : base(jsch)
        {
        }

        public KeyPairRSA(JSch jsch, byte[] n_array, byte[] pub_array, byte[] prv_array
            )
            : base(jsch)
        {
            // modulus   p multiply q
            // e         
            // d         e^-1 mod (p-1)(q-1)
            // prime p
            // prime q
            // prime exponent p  dmp1 == prv mod (p-1)
            // prime exponent q  dmq1 == prv mod (q-1)
            // coefficient  iqmp == modinv(q, p) == q^-1 mod p
            this.n_array = n_array;
            this.pub_array = pub_array;
            this.prv_array = prv_array;
            if (n_array != null)
            {
                key_size = (new BigInteger(n_array)).BitCount();
            }
        }

        /// <exception cref="NSch.JSchException"/>
        internal override void Generate(int key_size)
        {
            this.key_size = key_size;
            try
            {
                Type c = Sharpen.Runtime.GetType(JSch.GetConfig("keypairgen.rsa"));
                NSch.KeyPairGenRSA keypairgen = (NSch.KeyPairGenRSA)(System.Activator.CreateInstance
                    (c));
                keypairgen.Init(key_size);
                pub_array = keypairgen.GetE();
                prv_array = keypairgen.GetD();
                n_array = keypairgen.GetN();
                p_array = keypairgen.GetP();
                q_array = keypairgen.GetQ();
                ep_array = keypairgen.GetEP();
                eq_array = keypairgen.GetEQ();
                c_array = keypairgen.GetC();
                keypairgen = null;
            }
            catch (Exception e)
            {
                //System.err.println("KeyPairRSA: "+e); 
                if (e is Exception)
                {
                    throw new JSchException(e.ToString(), (Exception)e);
                }
                throw new JSchException(e.ToString());
            }
        }

        private static readonly byte[] begin = Util.Str2byte("-----BEGIN RSA PRIVATE KEY-----"
            );

        private static readonly byte[] end = Util.Str2byte("-----END RSA PRIVATE KEY-----"
            );

        internal override byte[] GetBegin()
        {
            return begin;
        }

        internal override byte[] GetEnd()
        {
            return end;
        }

        internal override byte[] GetPrivateKey()
        {
            int content = 1 + CountLength(1) + 1 + 1 + CountLength(n_array.Length) + n_array.
                Length + 1 + CountLength(pub_array.Length) + pub_array.Length + 1 + CountLength(
                prv_array.Length) + prv_array.Length + 1 + CountLength(p_array.Length) + p_array
                .Length + 1 + CountLength(q_array.Length) + q_array.Length + 1 + CountLength(ep_array
                .Length) + ep_array.Length + 1 + CountLength(eq_array.Length) + eq_array.Length 
                + 1 + CountLength(c_array.Length) + c_array.Length;
            // INTEGER
            // INTEGER  N
            // INTEGER  pub
            // INTEGER  prv
            // INTEGER  p
            // INTEGER  q
            // INTEGER  ep
            // INTEGER  eq
            // INTEGER  c
            int total = 1 + CountLength(content) + content;
            // SEQUENCE
            byte[] plain = new byte[total];
            int index = 0;
            index = WriteSEQUENCE(plain, index, content);
            index = WriteINTEGER(plain, index, new byte[1]);
            // 0
            index = WriteINTEGER(plain, index, n_array);
            index = WriteINTEGER(plain, index, pub_array);
            index = WriteINTEGER(plain, index, prv_array);
            index = WriteINTEGER(plain, index, p_array);
            index = WriteINTEGER(plain, index, q_array);
            index = WriteINTEGER(plain, index, ep_array);
            index = WriteINTEGER(plain, index, eq_array);
            index = WriteINTEGER(plain, index, c_array);
            return plain;
        }

        internal override bool Parse(byte[] plain)
        {
            try
            {
                int index = 0;
                int length = 0;
                if (vendor == VENDOR_PUTTY)
                {
                    Buffer buf = new Buffer(plain);
                    buf.Skip(plain.Length);
                    try
                    {
                        byte[][] tmp = buf.getBytes(4, string.Empty);
                        prv_array = tmp[0];
                        p_array = tmp[1];
                        q_array = tmp[2];
                        c_array = tmp[3];
                    }
                    catch (JSchException)
                    {
                        return false;
                    }
          					getEPArray();
          					getEQArray();
                    return true;
                }
                if (vendor == VENDOR_FSECURE)
                {
                    if (plain[index] != unchecked((int)(0x30)))
                    {
                        // FSecure
                        Buffer buf = new Buffer(plain);
                        pub_array = buf.GetMPIntBits();
                        prv_array = buf.GetMPIntBits();
                        n_array = buf.GetMPIntBits();
                        byte[] u_array = buf.GetMPIntBits();
                        p_array = buf.GetMPIntBits();
                        q_array = buf.GetMPIntBits();
            			if (n_array != null)
            			{
            				key_size = (new BigInteger(n_array)).BitCount();
            			}
            			getEPArray();
            			getEQArray();
            			getCArray();
                        return true;
                    }
                    return false;
                }
                /*
                Key must be in the following ASN.1 DER encoding,
                RSAPrivateKey ::= SEQUENCE {
                    version           Version,
                    modulus           INTEGER,  -- n
                    publicExponent    INTEGER,  -- e
                    privateExponent   INTEGER,  -- d
                    prime1            INTEGER,  -- p
                    prime2            INTEGER,  -- q
                    exponent1         INTEGER,  -- d mod (p-1)
                    exponent2         INTEGER,  -- d mod (q-1)
                    coefficient       INTEGER,  -- (inverse of q) mod p
                    otherPrimeInfos   OtherPrimeInfos OPTIONAL
                }
                */
                index++;
                // SEQUENCE
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                if (plain[index] != unchecked((int)(0x02)))
                {
                    return false;
                }
                index++;
                // INTEGER
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                index += length;
                index++;
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                n_array = new byte[length];
                System.Array.Copy(plain, index, n_array, 0, length);
                index += length;
                index++;
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                pub_array = new byte[length];
                System.Array.Copy(plain, index, pub_array, 0, length);
                index += length;
                index++;
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                prv_array = new byte[length];
                System.Array.Copy(plain, index, prv_array, 0, length);
                index += length;
                index++;
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                p_array = new byte[length];
                System.Array.Copy(plain, index, p_array, 0, length);
                index += length;
                index++;
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                q_array = new byte[length];
                System.Array.Copy(plain, index, q_array, 0, length);
                index += length;
                index++;
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                ep_array = new byte[length];
                System.Array.Copy(plain, index, ep_array, 0, length);
                index += length;
                index++;
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                eq_array = new byte[length];
                System.Array.Copy(plain, index, eq_array, 0, length);
                index += length;
                index++;
                length = plain[index++] & unchecked((int)(0xff));
                if ((length & unchecked((int)(0x80))) != 0)
                {
                    int foo = length & unchecked((int)(0x7f));
                    length = 0;
                    while (foo-- > 0)
                    {
                        length = (length << 8) + (plain[index++] & unchecked((int)(0xff)));
                    }
                }
                c_array = new byte[length];
                System.Array.Copy(plain, index, c_array, 0, length);
                index += length;
        		if (n_array != null)
        		{
        			key_size = (new BigInteger(n_array)).BitCount();
        		}
            }
            catch (Exception)
            {
                //System.err.println(e);
                return false;
            }
            return true;
        }

        public override byte[] GetPublicKeyBlob()
        {
            byte[] foo = base.GetPublicKeyBlob();
            if (foo != null)
            {
                return foo;
            }
            if (pub_array == null)
            {
                return null;
            }
            byte[][] tmp = new byte[3][];
            tmp[0] = sshrsa;
            tmp[1] = pub_array;
            tmp[2] = n_array;
            return Buffer.fromBytes(tmp).buffer;
        }

        private static readonly byte[] sshrsa = Util.Str2byte("ssh-rsa");

        internal override byte[] GetKeyTypeName()
        {
            return sshrsa;
        }

        public override int GetKeyType()
        {
            return RSA;
        }

        internal override int GetKeySize()
        {
            return key_size;
        }

/*
        public override byte[] GetSignature(byte[] data)
        {
            try
            {
                Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("signature.rsa"));
                NSch.SignatureRSA rsa = (NSch.SignatureRSA)(System.Activator.CreateInstance(c));
                rsa.Init();
                rsa.SetPrvKey(prv_array, n_array);
                rsa.Update(data);
                byte[] sig = rsa.Sign();
                byte[][] tmp = new byte[2][];
                tmp[0] = sshrsa;
                tmp[1] = sig;
                return Buffer.fromBytes(tmp).buffer;
            }
            catch (Exception)
            {
            }
            return null;
        }

        public override Signature GetVerifier()
        {
            try
            {
                Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("signature.rsa"));
                NSch.SignatureRSA rsa = (NSch.SignatureRSA)(System.Activator.CreateInstance(c));
                rsa.Init();
                if (pub_array == null && n_array == null && GetPublicKeyBlob() != null)
                {
                    Buffer buf = new Buffer(GetPublicKeyBlob());
                    buf.GetString();
                    pub_array = buf.GetString();
                    n_array = buf.GetString();
                }
                rsa.GetPubKey(pub_array, n_array);
                return rsa;
            }
            catch (Exception)
            {
            }
            return null;
        }
*/
        /// <exception cref="NSch.JSchException"/>
        internal static NSch.KeyPair FromSSHAgent(JSch jsch, Buffer buf)
        {
            byte[][] tmp = buf.getBytes(8, "invalid key format");
            byte[] n_array = tmp[1];
            byte[] pub_array = tmp[2];
            byte[] prv_array = tmp[3];
            NSch.KeyPairRSA kpair = new NSch.KeyPairRSA(jsch, n_array, pub_array, prv_array);
            kpair.c_array = tmp[4];
            // iqmp
            kpair.p_array = tmp[5];
            kpair.q_array = tmp[6];
            kpair.PublicKeyComment = Sharpen.Runtime.GetStringForBytes(tmp[7]);
            kpair.vendor = VENDOR_OPENSSH;
            return kpair;
        }
/*
        /// <exception cref="NSch.JSchException"/>
        public override byte[] ForSSHAgent()
        {
            if (isEncrypted())
            {
                throw new JSchException("key is encrypted.");
            }
            Buffer buf = new Buffer();
            buf.PutString(sshrsa);
            buf.PutString(n_array);
            buf.PutString(pub_array);
            buf.PutString(prv_array);
            buf.PutString(getCArray());
            buf.PutString(p_array);
            buf.PutString(q_array);
            buf.PutString(Util.Str2byte(PublicKeyComment));
            byte[] result = new byte[buf.GetLength()];
            buf.GetByte(result, 0, result.Length);
            return result;
        }
*/
        private byte[] getEPArray()
        {
            if (ep_array == null)
            {
                ep_array = (new BigInteger(prv_array) % (BigInteger.Subtract(new BigInteger(p_array), new BigInteger(1)))).GetBytes();
            }
            return ep_array;
        }

        private byte[] getEQArray()
        {
            if (eq_array == null)
            {
                ep_array = (new BigInteger(prv_array) % (BigInteger.Subtract(new BigInteger(q_array), new BigInteger(1)))).GetBytes();
            }
            return eq_array;
        }

        private byte[] getCArray()
        {
            if (c_array == null)
            {
                c_array = (new BigInteger(q_array)).ModInverse(new BigInteger(p_array)).GetBytes();
            }
            return c_array;
        }

        public override void Dispose()
        {
            base.Dispose();
            Util.Bzero(prv_array);
        }
    }
}
