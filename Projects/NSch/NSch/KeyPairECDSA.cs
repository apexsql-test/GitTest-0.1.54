/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2015-2016 ymnk, JCraft,Inc. All rights reserved.

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
*/
using System;
using Sharpen;

namespace NSch
{
	public class KeyPairECDSA : NSch.KeyPair
	{
		private static byte[][] oids = new byte[][] { new byte[] { unchecked((byte)0x06
			), unchecked((byte)0x08), unchecked((byte)0x2a), unchecked((byte)0x86), unchecked(
			(byte)0x48), unchecked((byte)0xce), unchecked((byte)0x3d), unchecked((byte)0x03
			), unchecked((byte)0x01), unchecked((byte)0x07) }, new byte[] { unchecked((byte
			)0x06), unchecked((byte)0x05), unchecked((byte)0x2b), unchecked((byte)0x81), 
			unchecked((byte)0x04), unchecked((byte)0x00), unchecked((byte)0x22) }, new byte
			[] { unchecked((byte)0x06), unchecked((byte)0x05), unchecked((byte)0x2b), unchecked(
			(byte)0x81), unchecked((byte)0x04), unchecked((byte)0x00), unchecked((byte)0x23
			) } };

		private static string[] names = new string[] { "nistp256", "nistp384", "nistp521"
			 };

		private byte[] name = Util.Str2byte(names[0]);

		private byte[] r_array;

		private byte[] s_array;

		private byte[] prv_array;

		private int key_size = 256;

		public KeyPairECDSA(JSch jsch)
			: this(jsch, null, null, null, null)
		{
		}

		public KeyPairECDSA(JSch jsch, byte[] name, byte[] r_array, byte[] s_array, byte
			[] prv_array)
			: base(jsch)
		{
			// 256
			// 384
			//521
			if (name != null)
			{
				this.name = name;
			}
			this.r_array = r_array;
			this.s_array = s_array;
			this.prv_array = prv_array;
			if (prv_array != null)
			{
				key_size = prv_array.Length >= 64 ? 521 : (prv_array.Length >= 48 ? 384 : 256);
			}
		}

		/// <exception cref="NSch.JSchException"/>
		internal override void Generate(int key_size)
		{
			this.key_size = key_size;
			try
			{
				Type c = Sharpen.Runtime.GetType(JSch.GetConfig("keypairgen.ecdsa"));
				KeyPairGenECDSA keypairgen = (KeyPairGenECDSA)(System.Activator.CreateInstance(c)
					);
				keypairgen.init(key_size);
				prv_array = keypairgen.getD();
				r_array = keypairgen.getR();
				s_array = keypairgen.getS();
				name = Util.Str2byte(names[prv_array.Length >= 64 ? 2 : (prv_array.Length >= 48 ? 
					1 : 0)]);
				keypairgen = null;
			}
			catch (Exception e)
			{
				if (e is Exception)
				{
					throw new JSchException(e.ToString(), (Exception)e);
				}
				throw new JSchException(e.ToString());
			}
		}

		private static readonly byte[] begin = Util.Str2byte("-----BEGIN EC PRIVATE KEY-----"
			);

		private static readonly byte[] end = Util.Str2byte("-----END EC PRIVATE KEY-----"
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
			byte[] tmp = new byte[1];
			tmp[0] = 1;
			byte[] oid = oids[(r_array.Length >= 64) ? 2 : ((r_array.Length >= 48) ? 1 : 0)];
			byte[] point = toPoint(r_array, s_array);
			int bar = ((point.Length + 1) & unchecked((int)(0x80))) == 0 ? 3 : 4;
			byte[] foo = new byte[point.Length + bar];
			System.Array.Copy(point, 0, foo, bar, point.Length);
			foo[0] = unchecked((int)(0x03));
			// BITSTRING 
			if (bar == 3)
			{
				foo[1] = unchecked((byte)(point.Length + 1));
			}
			else
			{
				foo[1] = unchecked((byte)0x81);
				foo[2] = unchecked((byte)(point.Length + 1));
			}
			point = foo;
			int content = 1 + CountLength(tmp.Length) + tmp.Length + 1 + CountLength(prv_array
				.Length) + prv_array.Length + 1 + CountLength(oid.Length) + oid.Length + 1 + CountLength
				(point.Length) + point.Length;
			int total = 1 + CountLength(content) + content;
			// SEQUENCE
			byte[] plain = new byte[total];
			int index = 0;
			index = WriteSEQUENCE(plain, index, content);
			index = WriteINTEGER(plain, index, tmp);
			index = writeOCTETSTRING(plain, index, prv_array);
			index = writeDATA(plain, unchecked((byte)0xa0), index, oid);
			index = writeDATA(plain, unchecked((byte)0xa1), index, point);
			return plain;
		}

		internal override bool Parse(byte[] plain)
		{
			try
			{
				if (vendor == VENDOR_FSECURE)
				{
        /*
	if(plain[0]!=0x30){              // FSecure
	  return true;
	}
	return false;
        */
					return false;
				}
				else
				{
					if (vendor == VENDOR_PUTTY)
					{
        /*
        Buffer buf=new Buffer(plain);
        buf.skip(plain.length);

        try {
          byte[][] tmp = buf.getBytes(1, "");
          prv_array = tmp[0];
        }
        catch(JSchException e){
          return false;
        }

        return true;
        */
						return false;
					}
				}
				int index = 0;
				int length = 0;
				if (plain[index] != unchecked((int)(0x30)))
				{
					return false;
				}
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
				// 0x04
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
				// 0xa0
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
				byte[] oid_array = new byte[length];
				System.Array.Copy(plain, index, oid_array, 0, length);
				index += length;
				for (int i = 0; i < oids.Length; i++)
				{
					if (Util.Array_equals(oids[i], oid_array))
					{
						name = Util.Str2byte(names[i]);
						break;
					}
				}
				index++;
				// 0xa1
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
				byte[] Q_array = new byte[length];
				System.Array.Copy(plain, index, Q_array, 0, length);
				index += length;
				byte[][] tmp = fromPoint(Q_array);
				r_array = tmp[0];
				s_array = tmp[1];
				if (prv_array != null)
				{
					key_size = prv_array.Length >= 64 ? 521 : (prv_array.Length >= 48 ? 384 : 256);
				}
			}
			catch (Exception)
			{
				//System.err.println(e);
				//e.printStackTrace();
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
			if (r_array == null)
			{
				return null;
			}
			byte[][] tmp = new byte[3][];
			tmp[0] = Util.Str2byte("ecdsa-sha2-" + Sharpen.Runtime.GetStringForBytes(name));
			tmp[1] = name;
			tmp[2] = new byte[1 + r_array.Length + s_array.Length];
			tmp[2][0] = 4;
			// POINT_CONVERSION_UNCOMPRESSED
			System.Array.Copy(r_array, 0, tmp[2], 1, r_array.Length);
			System.Array.Copy(s_array, 0, tmp[2], 1 + r_array.Length, s_array.Length);
			return Buffer.fromBytes(tmp).buffer;
		}

		internal override byte[] GetKeyTypeName()
		{
			return Util.Str2byte("ecdsa-sha2-" + Sharpen.Runtime.GetStringForBytes(name));
		}

		public override int GetKeyType()
		{
			return ECDSA;
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
				Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("signature.ecdsa"));
				SignatureECDSA ecdsa = (SignatureECDSA)(System.Activator.CreateInstance(c));
				ecdsa.Init();
				ecdsa.SetPrvKey(prv_array);
				ecdsa.Update(data);
				byte[] sig = ecdsa.sign();
				byte[][] tmp = new byte[2][];
				tmp[0] = Util.Str2byte("ecdsa-sha2-" + Sharpen.Runtime.GetStringForBytes(name));
				tmp[1] = sig;
				return Buffer.fromBytes(tmp).buffer;
			}
			catch (Exception)
			{
			}
			//System.err.println("e "+e);
			return null;
		}

		public override Signature GetVerifier()
		{
			try
			{
				Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("signature.ecdsa"));
				SignatureECDSA ecdsa = (SignatureECDSA)(System.Activator.CreateInstance(c));
				ecdsa.Init();
				if (r_array == null && s_array == null && GetPublicKeyBlob() != null)
				{
					Buffer buf = new Buffer(GetPublicKeyBlob());
					buf.GetString();
					// ecdsa-sha2-nistp256
					buf.GetString();
					// nistp256
					byte[][] tmp = fromPoint(buf.getString());
					r_array = tmp[0];
					s_array = tmp[1];
				}
				ecdsa.SetPubKey(r_array, s_array);
				return ecdsa;
			}
			catch (Exception)
			{
			}
			//System.err.println("e "+e);
			return null;
		}
*/
		/// <exception cref="NSch.JSchException"/>
		internal static NSch.KeyPair FromSSHAgent(JSch jsch, Buffer buf)
		{
			byte[][] tmp = buf.getBytes(5, "invalid key format");
			byte[] name = tmp[1];
			// nistp256
			byte[][] foo = fromPoint(tmp[2]);
			byte[] r_array = foo[0];
			byte[] s_array = foo[1];
			byte[] prv_array = tmp[3];
			NSch.KeyPairECDSA kpair = new NSch.KeyPairECDSA(jsch, name, r_array, s_array, prv_array
				);
			kpair.PublicKeyComment = Sharpen.Runtime.GetStringForBytes(tmp[4]);
			kpair.vendor = VENDOR_OPENSSH;
			return kpair;
		}

/*
		/// <exception cref="NSch.JSchException"/>
		public override byte[] ForSSHAgent()
		{
			if (IsEncrypted())
			{
				throw new JSchException("key is encrypted.");
			}
			Buffer buf = new Buffer();
			buf.PutString(Util.Str2byte("ecdsa-sha2-" + Sharpen.Runtime.GetStringForBytes(name
				)));
			buf.PutString(name);
			buf.PutString(toPoint(r_array, s_array));
			buf.PutString(prv_array);
			buf.PutString(Util.Str2byte(PublicKeyComment));
			byte[] result = new byte[buf.GetLength()];
			buf.GetByte(result, 0, result.Length);
			return result;
		}
 */ 

		internal static byte[] toPoint(byte[] r_array, byte[] s_array)
		{
			byte[] tmp = new byte[1 + r_array.Length + s_array.Length];
			tmp[0] = unchecked((int)(0x04));
			System.Array.Copy(r_array, 0, tmp, 1, r_array.Length);
			System.Array.Copy(s_array, 0, tmp, 1 + r_array.Length, s_array.Length);
			return tmp;
		}

		internal static byte[][] fromPoint(byte[] point)
		{
			int i = 0;
			while (point[i] != 4)
			{
				i++;
			}
			i++;
			byte[][] tmp = new byte[2][];
			byte[] r_array = new byte[(point.Length - i) / 2];
			byte[] s_array = new byte[(point.Length - i) / 2];
			// point[0] == 0x04 == POINT_CONVERSION_UNCOMPRESSED
			System.Array.Copy(point, i, r_array, 0, r_array.Length);
			System.Array.Copy(point, i + r_array.Length, s_array, 0, s_array.Length);
			tmp[0] = r_array;
			tmp[1] = s_array;
			return tmp;
		}

		public override void Dispose()
		{
			base.Dispose();
			Util.Bzero(prv_array);
		}
	}
}
