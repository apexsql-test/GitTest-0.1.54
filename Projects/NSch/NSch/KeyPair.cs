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
using System.Collections;
using NSch;
using Sharpen;

namespace NSch
{
	public abstract class KeyPair
	{
		public const int ERROR = 0;

		public const int DSA = 1;

		public const int RSA = 2;

		public const int ECDSA = 3;

		public const int UNKNOWN = 4;

		internal const int VENDOR_OPENSSH = 0;

		internal const int VENDOR_FSECURE = 1;

		internal const int VENDOR_PUTTY = 2;

		internal const int VENDOR_PKCS8 = 3;

		internal int vendor = VENDOR_OPENSSH;

		private static readonly byte[] cr = Util.Str2byte("\n");

		/// <exception cref="NSch.JSchException"/>
		public static NSch.KeyPair GenKeyPair(JSch jsch, int type)
		{
			return GenKeyPair(jsch, type, 1024);
		}

		/// <exception cref="NSch.JSchException"/>
		public static NSch.KeyPair GenKeyPair(JSch jsch, int type, int key_size)
		{
			NSch.KeyPair kpair = null;
			if (type == DSA)
			{
				kpair = new KeyPairDSA(jsch);
			}
			else
			{
				if (type == RSA)
				{
					kpair = new KeyPairRSA(jsch);
				}
			}
			if (kpair != null)
			{
				kpair.Generate(key_size);
			}
			return kpair;
		}

		/// <exception cref="NSch.JSchException"/>
		internal abstract void Generate(int key_size);

		internal abstract byte[] GetBegin();

		internal abstract byte[] GetEnd();

		internal abstract int GetKeySize();

		public virtual string GetPublicKeyComment()
		{
			return PublicKeyComment;
		}

		protected string PublicKeyComment = string.Empty;

		internal JSch jsch = null;

		private NSch.Cipher cipher;

		private HASH hash;

		private Random random;

		private byte[] passphrase;

		public KeyPair(JSch jsch)
		{
			this.jsch = jsch;
		}

		internal static byte[][] header = new byte[][] { Util.Str2byte("Proc-Type: 4,ENCRYPTED"
			), Util.Str2byte("DEK-Info: DES-EDE3-CBC,") };

		internal abstract byte[] GetPrivateKey();

		/// <summary>Writes the plain private key to the given output stream.</summary>
		/// <param name="out">output stream</param>
		/// <seealso cref="writePrivateKey(Sharpen.OutputStream, byte[])"/>
		public virtual void WritePrivateKey(OutputStream @out)
		{
            this.WritePrivateKey(@out, null);
		}

		/// <summary>Writes the cyphered private key to the given output stream.</summary>
		/// <param name="out">output stream</param>
		/// <param name="passphrase">a passphrase to encrypt the private key</param>
        public virtual void WritePrivateKey(OutputStream @out, byte[] passphrase)
		{
			if (passphrase == null)
			{
				passphrase = this.passphrase;
			}
			byte[] plain = GetPrivateKey();
			byte[][] _iv = new byte[1][];
            byte[] encoded = Encrypt(plain, _iv, passphrase);
			if (encoded != plain)
			{
				Util.Bzero(plain);
			}
			byte[] iv = _iv[0];
			byte[] prv = Util.ToBase64(encoded, 0, encoded.Length);
			try
			{
				@out.Write(GetBegin());
				@out.Write(cr);
				if (passphrase != null)
				{
					@out.Write(header[0]);
					@out.Write(cr);
					@out.Write(header[1]);
					for (int i = 0; i < iv.Length; i++)
					{
						@out.Write(B2a(unchecked((byte)((iv[i] >> 4) & unchecked((int)(0x0f))))));
						@out.Write(B2a(unchecked((byte)(iv[i] & unchecked((int)(0x0f))))));
					}
					@out.Write(cr);
					@out.Write(cr);
				}
				int i_1 = 0;
				while (i_1 < prv.Length)
				{
					if (i_1 + 64 < prv.Length)
					{
						@out.Write(prv, i_1, 64);
						@out.Write(cr);
						i_1 += 64;
						continue;
					}
					@out.Write(prv, i_1, prv.Length - i_1);
					@out.Write(cr);
					break;
				}
				@out.Write(GetEnd());
				@out.Write(cr);
			}
			catch (Exception)
			{
			}
		}

		private static byte[] space = Util.Str2byte(" ");

		//out.close();
		internal abstract byte[] GetKeyTypeName();

		public abstract int GetKeyType();

		/// <summary>Returns the blob of the public key.</summary>
		/// <returns>blob of the public key</returns>
		public virtual byte[] GetPublicKeyBlob()
		{
			// TODO JSchException should be thrown
			//if(publickeyblob == null)
			//  throw new JSchException("public-key blob is not available");
			return publickeyblob;
		}

		/// <summary>Writes the public key with the specified comment to the output stream.</summary>
		/// <param name="out">output stream</param>
		/// <param name="comment">comment</param>
		public virtual void WritePublicKey(OutputStream @out, string comment)
		{
			byte[] pubblob = GetPublicKeyBlob();
			byte[] pub = Util.ToBase64(pubblob, 0, pubblob.Length);
			try
			{
				@out.Write(GetKeyTypeName());
				@out.Write(space);
				@out.Write(pub, 0, pub.Length);
				@out.Write(space);
				@out.Write(Util.Str2byte(comment));
				@out.Write(cr);
			}
			catch (Exception)
			{
			}
		}

		/// <summary>Writes the public key with the specified comment to the file.</summary>
		/// <param name="name">file name</param>
		/// <param name="comment">comment</param>
		/// <seealso cref="writePublicKey(Sharpen.OutputStream, string)"/>
		/// <exception cref="System.IO.FileNotFoundException"/>
		/// <exception cref="System.IO.IOException"/>
		public virtual void WritePublicKey(string name, string comment)
		{
			FileOutputStream fos = new FileOutputStream(name);
			WritePublicKey(fos, comment);
			fos.Close();
		}

		/// <summary>
		/// Writes the public key with the specified comment to the output stream in
		/// the format defined in http://www.ietf.org/rfc/rfc4716.txt
		/// </summary>
		/// <param name="out">output stream</param>
		/// <param name="comment">comment</param>
		public virtual void WriteSECSHPublicKey(OutputStream @out, string comment)
		{
			byte[] pubblob = GetPublicKeyBlob();
			byte[] pub = Util.ToBase64(pubblob, 0, pubblob.Length);
			try
			{
				@out.Write(Util.Str2byte("---- BEGIN SSH2 PUBLIC KEY ----"));
				@out.Write(cr);
				@out.Write(Util.Str2byte("Comment: \"" + comment + "\""));
				@out.Write(cr);
				int index = 0;
				while (index < pub.Length)
				{
					int len = 70;
					if ((pub.Length - index) < len)
					{
						len = pub.Length - index;
					}
					@out.Write(pub, index, len);
					@out.Write(cr);
					index += len;
				}
				@out.Write(Util.Str2byte("---- END SSH2 PUBLIC KEY ----"));
				@out.Write(cr);
			}
			catch (Exception)
			{
			}
		}

		/// <summary>
		/// Writes the public key with the specified comment to the output stream in
		/// the format defined in http://www.ietf.org/rfc/rfc4716.txt
		/// </summary>
		/// <param name="name">file name</param>
		/// <param name="comment">comment</param>
		/// <seealso cref="writeSECSHPublicKey(Sharpen.OutputStream, string)"/>
		/// <exception cref="System.IO.FileNotFoundException"/>
		/// <exception cref="System.IO.IOException"/>
		public virtual void WriteSECSHPublicKey(string name, string comment)
		{
			FileOutputStream fos = new FileOutputStream(name);
			WriteSECSHPublicKey(fos, comment);
			fos.Close();
		}

		/// <summary>Writes the plain private key to the file.</summary>
		/// <param name="name">file name</param>
		/// <seealso cref="writePrivateKey(string, byte[])"/>
		/// <exception cref="System.IO.FileNotFoundException"/>
		/// <exception cref="System.IO.IOException"/>
		public virtual void WritePrivateKey(string name)
		{
			this.WritePrivateKey(name, null);
		}

		/// <summary>Writes the cyphered private key to the file.</summary>
		/// <param name="name">file name</param>
		/// <param name="passphrase">a passphrase to encrypt the private key</param>
		/// <seealso cref="writePrivateKey(Sharpen.OutputStream, byte[])"/>
		/// <exception cref="System.IO.FileNotFoundException"/>
		/// <exception cref="System.IO.IOException"/>
		public virtual void WritePrivateKey(string name, byte[] passphrase)
		{
			FileOutputStream fos = new FileOutputStream(name);
			WritePrivateKey(fos, passphrase);
			fos.Close();
		}

		/// <summary>Returns the finger-print of the public key.</summary>
		/// <returns>finger print</returns>
		public virtual string GetFingerPrint()
		{
			if (hash == null)
			{
				hash = GenHash();
			}
			byte[] kblob = GetPublicKeyBlob();
			if (kblob == null)
			{
				return null;
			}
			return Util.GetFingerPrint(hash, kblob);
		}

		private byte[] Encrypt(byte[] plain, byte[][] _iv, byte[] passphrase)
		{
			if (passphrase == null)
			{
				return plain;
			}
			if (cipher == null)
			{
				cipher = GenCipher();
			}
			byte[] iv = _iv[0] = new byte[cipher.GetIVSize()];
			if (random == null)
			{
				random = GenRandom();
			}
			random.Fill(iv, 0, iv.Length);
			byte[] key = GenKey(passphrase, iv);
			byte[] encoded = plain;
			{
				// PKCS#5Padding
				//int bsize=cipher.getBlockSize();
				int bsize = cipher.GetIVSize();
				byte[] foo = new byte[(encoded.Length / bsize + 1) * bsize];
				System.Array.Copy(encoded, 0, foo, 0, encoded.Length);
				int padding = bsize - encoded.Length % bsize;
				for (int i = foo.Length - 1; (foo.Length - padding) <= i; i--)
				{
					foo[i] = unchecked((byte)padding);
				}
				encoded = foo;
			}
			try
			{
				cipher.Init(NSch.Cipher.ENCRYPT_MODE, key, iv);
				cipher.Update(encoded, 0, encoded.Length, encoded, 0);
			}
			catch (Exception)
			{
			}
			//System.err.println(e);
			Util.Bzero(key);
			return encoded;
		}

		internal abstract bool Parse(byte[] data);

		private byte[] Decrypt(byte[] data, byte[] passphrase, byte[] iv)
		{
			try
			{
				byte[] key = GenKey(passphrase, iv);
				cipher.Init(NSch.Cipher.DECRYPT_MODE, key, iv);
				Util.Bzero(key);
				byte[] plain = new byte[data.Length];
				cipher.Update(data, 0, data.Length, plain, 0);
				return plain;
			}
			catch (Exception)
			{
			}
			//System.err.println(e);
			return null;
		}

		internal virtual int WriteSEQUENCE(byte[] buf, int index, int len)
		{
			buf[index++] = unchecked((int)(0x30));
			index = WriteLength(buf, index, len);
			return index;
		}

		internal virtual int WriteINTEGER(byte[] buf, int index, byte[] data)
		{
			buf[index++] = unchecked((int)(0x02));
			index = WriteLength(buf, index, data.Length);
			System.Array.Copy(data, 0, buf, index, data.Length);
			index += data.Length;
			return index;
		}

		internal virtual int writeOCTETSTRING(byte[] buf, int index, byte[] data)
		{
			buf[index++] = unchecked((int)(0x04));
			index = WriteLength(buf, index, data.Length);
			System.Array.Copy(data, 0, buf, index, data.Length);
			index += data.Length;
			return index;
		}

		internal virtual int writeDATA(byte[] buf, byte n, int index, byte[] data)
		{
			buf[index++] = n;
			index = WriteLength(buf, index, data.Length);
			System.Array.Copy(data, 0, buf, index, data.Length);
			index += data.Length;
			return index;
		}

		internal virtual int CountLength(int len)
		{
			int i = 1;
			if (len <= unchecked((int)(0x7f)))
			{
				return i;
			}
			while (len > 0)
			{
				len = (int)(((uint)len) >> 8);
				i++;
			}
			return i;
		}

		internal virtual int WriteLength(byte[] data, int index, int len)
		{
			int i = CountLength(len) - 1;
			if (i == 0)
			{
				data[index++] = unchecked((byte)len);
				return index;
			}
			data[index++] = unchecked((byte)(unchecked((int)(0x80)) | i));
			int j = index + i;
			while (i > 0)
			{
				data[index + i - 1] = unchecked((byte)(len & unchecked((int)(0xff))));
				len = (int)(((uint)len) >> 8);
				i--;
			}
			return j;
		}

		private Random GenRandom()
		{
			if (random == null)
			{
				try
				{
					Type c = Sharpen.Runtime.GetType(JSch.GetConfig("random"));
					random = (Random)(System.Activator.CreateInstance(c));
				}
				catch (Exception e)
				{
					System.Console.Error.WriteLine("connect: random " + e);
				}
			}
			return random;
		}

		private HASH GenHash()
		{
			try
			{
				Type c = Sharpen.Runtime.GetType(JSch.GetConfig("md5"));
				hash = (HASH)(System.Activator.CreateInstance(c));
				hash.Init();
			}
			catch (Exception)
			{
			}
			return hash;
		}

		private NSch.Cipher GenCipher()
		{
			try
			{
				Type c;
				c = Sharpen.Runtime.GetType(JSch.GetConfig("3des-cbc"));
				cipher = (NSch.Cipher)(System.Activator.CreateInstance(c));
			}
			catch (Exception)
			{
			}
			return cipher;
		}

		internal virtual byte[] GenKey(byte[] passphrase, byte[] iv)
		{
			lock (this)
			{
				if (cipher == null)
				{
					cipher = GenCipher();
				}
				if (hash == null)
				{
					hash = GenHash();
				}
				byte[] key = new byte[cipher.GetBlockSize()];
				int hsize = hash.GetBlockSize();
				byte[] hn = new byte[key.Length / hsize * hsize + (key.Length % hsize == 0 ? 0 : 
					hsize)];
				try
				{
					byte[] tmp = null;
					if (vendor == VENDOR_OPENSSH)
					{
						for (int index = 0; index + hsize <= hn.Length; )
						{
							if (tmp != null)
							{
								hash.Update(tmp, 0, tmp.Length);
							}
							hash.Update(passphrase, 0, passphrase.Length);
							hash.Update(iv, 0, iv.Length > 8 ? 8 : iv.Length);
							tmp = hash.Digest();
							System.Array.Copy(tmp, 0, hn, index, tmp.Length);
							index += tmp.Length;
						}
						System.Array.Copy(hn, 0, key, 0, key.Length);
					}
					else
					{
						if (vendor == VENDOR_FSECURE)
						{
							for (int index = 0; index + hsize <= hn.Length; )
							{
								if (tmp != null)
								{
									hash.Update(tmp, 0, tmp.Length);
								}
								hash.Update(passphrase, 0, passphrase.Length);
								tmp = hash.Digest();
								System.Array.Copy(tmp, 0, hn, index, tmp.Length);
								index += tmp.Length;
							}
							System.Array.Copy(hn, 0, key, 0, key.Length);
						}
					}
				}
				catch (Exception e)
				{
					System.Console.Error.WriteLine(e);
				}
				return key;
			}
		}

		[System.ObsoleteAttribute(@"use #writePrivateKey(java.io.OutputStream out, byte[] passphrase)"
			)]
		public virtual void SetPassphrase(string passphrase)
		{
			if (passphrase == null || passphrase.Length == 0)
			{
				SetPassphrase((byte[])null);
			}
			else
			{
				SetPassphrase(Util.Str2byte(passphrase));
			}
		}

		[System.ObsoleteAttribute(@"use #writePrivateKey(String name, byte[] passphrase)"
			)]
		public virtual void SetPassphrase(byte[] passphrase)
		{
			if (passphrase != null && passphrase.Length == 0)
			{
				passphrase = null;
			}
			this.passphrase = passphrase;
		}

		private bool encrypted = false;

		private byte[] data = null;

		private byte[] iv = null;

		private byte[] publickeyblob = null;

		public virtual bool IsEncrypted()
		{
			return encrypted;
		}

		public virtual bool Decrypt(string _passphrase)
		{
			if (_passphrase == null || _passphrase.Length == 0)
			{
				return !encrypted;
			}
			return Decrypt(Util.Str2byte(_passphrase));
		}

		public virtual bool Decrypt(byte[] _passphrase)
		{
			if (!encrypted)
			{
				return true;
			}
			if (_passphrase == null)
			{
				return !encrypted;
			}
			byte[] bar = new byte[_passphrase.Length];
			System.Array.Copy(_passphrase, 0, bar, 0, bar.Length);
			_passphrase = bar;
			byte[] foo = Decrypt(data, _passphrase, iv);
			Util.Bzero(_passphrase);
			if (Parse(foo))
			{
				encrypted = false;
			}
			return !encrypted;
		}

		/// <exception cref="NSch.JSchException"/>
		public static NSch.KeyPair Load(JSch jsch, string prvkey)
		{
			string pubkey = prvkey + ".pub";
			if (!new FilePath(pubkey).Exists())
			{
				pubkey = null;
			}
			return Load(jsch, prvkey, pubkey);
		}

		/// <exception cref="NSch.JSchException"/>
		public static NSch.KeyPair Load(JSch jsch, string prvkey, string pubkey)
		{
			byte[] iv = new byte[8];
			// 8
			bool encrypted = true;
			byte[] data = null;
			byte[] publickeyblob = null;
			int type = ERROR;
			int vendor = VENDOR_OPENSSH;
			string PublicKeyComment = string.Empty;
			NSch.Cipher cipher = null;
			try
			{
				FilePath file = new FilePath(prvkey);
				FileInputStream fis = new FileInputStream(prvkey);
				byte[] buf = new byte[(int)(file.Length())];
				int len = 0;
				while (true)
				{
					int i = fis.Read(buf, len, buf.Length - len);
					if (i <= 0)
					{
						break;
					}
					len += i;
				}
				fis.Close();
				int i_1 = 0;
				while (i_1 < len)
				{
					if (buf[i_1] == '-' && i_1 + 4 < len && buf[i_1 + 1] == '-' && buf[i_1 + 2] == '-'
						 && buf[i_1 + 3] == '-' && buf[i_1 + 4] == '-')
					{
						break;
					}
					i_1++;
				}
				while (i_1 < len)
				{
					if (buf[i_1] == 'B' && i_1 + 3 < len && buf[i_1 + 1] == 'E' && buf[i_1 + 2] == 'G'
						 && buf[i_1 + 3] == 'I')
					{
						i_1 += 6;
						if (buf[i_1] == 'D' && buf[i_1 + 1] == 'S' && buf[i_1 + 2] == 'A')
						{
							type = DSA;
						}
						else
						{
							if (buf[i_1] == 'R' && buf[i_1 + 1] == 'S' && buf[i_1 + 2] == 'A')
							{
								type = RSA;
							}
							else
							{
								if (buf[i_1] == 'S' && buf[i_1 + 1] == 'S' && buf[i_1 + 2] == 'H')
								{
									// FSecure
									type = UNKNOWN;
									vendor = VENDOR_FSECURE;
								}
								else
								{
									throw new JSchException("invalid privatekey: " + prvkey);
								}
							}
						}
						i_1 += 3;
						continue;
					}
					if (buf[i_1] == 'A' && i_1 + 7 < len && buf[i_1 + 1] == 'E' && buf[i_1 + 2] == 'S'
						 && buf[i_1 + 3] == '-' && buf[i_1 + 4] == '2' && buf[i_1 + 5] == '5' && buf[i_1
						 + 6] == '6' && buf[i_1 + 7] == '-')
					{
						i_1 += 8;
						if (Session.CheckCipher((string)JSch.GetConfig("aes256-cbc")))
						{
							Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("aes256-cbc"));
							cipher = (NSch.Cipher)(System.Activator.CreateInstance(c));
							// key=new byte[cipher.getBlockSize()];
							iv = new byte[cipher.GetIVSize()];
						}
						else
						{
							throw new JSchException("privatekey: aes256-cbc is not available " + prvkey);
						}
						continue;
					}
					if (buf[i_1] == 'A' && i_1 + 7 < len && buf[i_1 + 1] == 'E' && buf[i_1 + 2] == 'S'
						 && buf[i_1 + 3] == '-' && buf[i_1 + 4] == '1' && buf[i_1 + 5] == '9' && buf[i_1
						 + 6] == '2' && buf[i_1 + 7] == '-')
					{
						i_1 += 8;
						if (Session.CheckCipher((string)JSch.GetConfig("aes192-cbc")))
						{
							Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("aes192-cbc"));
							cipher = (NSch.Cipher)(System.Activator.CreateInstance(c));
							// key=new byte[cipher.getBlockSize()];
							iv = new byte[cipher.GetIVSize()];
						}
						else
						{
							throw new JSchException("privatekey: aes192-cbc is not available " + prvkey);
						}
						continue;
					}
					if (buf[i_1] == 'A' && i_1 + 7 < len && buf[i_1 + 1] == 'E' && buf[i_1 + 2] == 'S'
						 && buf[i_1 + 3] == '-' && buf[i_1 + 4] == '1' && buf[i_1 + 5] == '2' && buf[i_1
						 + 6] == '8' && buf[i_1 + 7] == '-')
					{
						i_1 += 8;
						if (Session.CheckCipher((string)JSch.GetConfig("aes128-cbc")))
						{
							Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("aes128-cbc"));
							cipher = (NSch.Cipher)(System.Activator.CreateInstance(c));
							// key=new byte[cipher.getBlockSize()];
							iv = new byte[cipher.GetIVSize()];
						}
						else
						{
							throw new JSchException("privatekey: aes128-cbc is not available " + prvkey);
						}
						continue;
					}
					if (buf[i_1] == 'C' && i_1 + 3 < len && buf[i_1 + 1] == 'B' && buf[i_1 + 2] == 'C'
						 && buf[i_1 + 3] == ',')
					{
						i_1 += 4;
						for (int ii = 0; ii < iv.Length; ii++)
						{
							iv[ii] = unchecked((byte)(((A2b(buf[i_1++]) << 4) & unchecked((int)(0xf0))) + (A2b
								(buf[i_1++]) & unchecked((int)(0xf)))));
						}
						continue;
					}
					if (buf[i_1] == unchecked((int)(0x0d)) && i_1 + 1 < buf.Length && buf[i_1 + 1] ==
						 unchecked((int)(0x0a)))
					{
						i_1++;
						continue;
					}
					if (buf[i_1] == unchecked((int)(0x0a)) && i_1 + 1 < buf.Length)
					{
						if (buf[i_1 + 1] == unchecked((int)(0x0a)))
						{
							i_1 += 2;
							break;
						}
						if (buf[i_1 + 1] == unchecked((int)(0x0d)) && i_1 + 2 < buf.Length && buf[i_1 + 2
							] == unchecked((int)(0x0a)))
						{
							i_1 += 3;
							break;
						}
						bool inheader = false;
						for (int j = i_1 + 1; j < buf.Length; j++)
						{
							if (buf[j] == unchecked((int)(0x0a)))
							{
								break;
							}
							//if(buf[j]==0x0d) break;
							if (buf[j] == ':')
							{
								inheader = true;
								break;
							}
						}
						if (!inheader)
						{
							i_1++;
							encrypted = false;
							// no passphrase
							break;
						}
					}
					i_1++;
				}
				if (type == ERROR)
				{
					throw new JSchException("invalid privatekey: " + prvkey);
				}
				int start = i_1;
				while (i_1 < len)
				{
					if (buf[i_1] == unchecked((int)(0x0a)))
					{
						bool xd = (buf[i_1 - 1] == unchecked((int)(0x0d)));
						System.Array.Copy(buf, i_1 + 1, buf, i_1 - (xd ? 1 : 0), len - i_1 - 1 - (xd ? 1 : 
							0));
						if (xd)
						{
							len--;
						}
						len--;
						continue;
					}
					if (buf[i_1] == '-')
					{
						break;
					}
					i_1++;
				}
				data = Util.FromBase64(buf, start, i_1 - start);
				if (data.Length > 4 && data[0] == unchecked((byte)unchecked((int)(0x3f))) && data
					[1] == unchecked((byte)unchecked((int)(0x6f))) && data[2] == unchecked((byte)unchecked(
					(int)(0xf9))) && data[3] == unchecked((byte)unchecked((int)(0xeb))))
				{
					// FSecure
					Buffer _buf = new Buffer(data);
					_buf.GetInt();
					// 0x3f6ff9be
					_buf.GetInt();
					byte[] _type = _buf.GetString();
					//System.err.println("type: "+new String(_type)); 
					string _cipher = Util.Byte2str(_buf.GetString());
					//System.err.println("cipher: "+_cipher); 
					if (_cipher.Equals("3des-cbc"))
					{
						_buf.GetInt();
						byte[] foo = new byte[data.Length - _buf.GetOffSet()];
						_buf.GetByte(foo);
						data = foo;
						encrypted = true;
						throw new JSchException("unknown privatekey format: " + prvkey);
					}
					else
					{
						if (_cipher.Equals("none"))
						{
							_buf.GetInt();
							_buf.GetInt();
							encrypted = false;
							byte[] foo = new byte[data.Length - _buf.GetOffSet()];
							_buf.GetByte(foo);
							data = foo;
						}
					}
				}
				if (pubkey != null)
				{
					try
					{
						file = new FilePath(pubkey);
						fis = new FileInputStream(pubkey);
						buf = new byte[(int)(file.Length())];
						len = 0;
						while (true)
						{
							i_1 = fis.Read(buf, len, buf.Length - len);
							if (i_1 <= 0)
							{
								break;
							}
							len += i_1;
						}
						fis.Close();
						if (buf.Length > 4 && buf[0] == '-' && buf[1] == '-' && buf[2] == '-' && buf[3] ==
							 '-')
						{
							// FSecure's public key
							bool valid = true;
							i_1 = 0;
							do
							{
								i_1++;
							}
							while (buf.Length > i_1 && buf[i_1] != unchecked((int)(0x0a)));
							if (buf.Length <= i_1)
							{
								valid = false;
							}
							while (valid)
							{
								if (buf[i_1] == unchecked((int)(0x0a)))
								{
									bool inheader = false;
									for (int j = i_1 + 1; j < buf.Length; j++)
									{
										if (buf[j] == unchecked((int)(0x0a)))
										{
											break;
										}
										if (buf[j] == ':')
										{
											inheader = true;
											break;
										}
									}
									if (!inheader)
									{
										i_1++;
										break;
									}
								}
								i_1++;
							}
							if (buf.Length <= i_1)
							{
								valid = false;
							}
							start = i_1;
							while (valid && i_1 < len)
							{
								if (buf[i_1] == unchecked((int)(0x0a)))
								{
									System.Array.Copy(buf, i_1 + 1, buf, i_1, len - i_1 - 1);
									len--;
									continue;
								}
								if (buf[i_1] == '-')
								{
									break;
								}
								i_1++;
							}
							if (valid)
							{
								publickeyblob = Util.FromBase64(buf, start, i_1 - start);
								if (type == UNKNOWN)
								{
									if (publickeyblob[8] == 'd')
									{
										type = DSA;
									}
									else
									{
										if (publickeyblob[8] == 'r')
										{
											type = RSA;
										}
									}
								}
							}
						}
						else
						{
							if (buf[0] == 's' && buf[1] == 's' && buf[2] == 'h' && buf[3] == '-')
							{
								i_1 = 0;
								while (i_1 < len)
								{
									if (buf[i_1] == ' ')
									{
										break;
									}
									i_1++;
								}
								i_1++;
								if (i_1 < len)
								{
									start = i_1;
									while (i_1 < len)
									{
										if (buf[i_1] == ' ')
										{
											break;
										}
										i_1++;
									}
									publickeyblob = Util.FromBase64(buf, start, i_1 - start);
								}
								if (i_1++ < len)
								{
									int s = i_1;
									while (i_1 < len)
									{
										if (buf[i_1] == '\n')
										{
											break;
										}
										i_1++;
									}
									if (i_1 < len)
									{
										PublicKeyComment = Sharpen.Runtime.GetStringForBytes(buf, s, i_1 - s);
									}
								}
							}
						}
					}
					catch (Exception)
					{
					}
				}
			}
			catch (Exception e)
			{
				if (e is JSchException)
				{
					throw (JSchException)e;
				}
				if (e is Exception)
				{
					throw new JSchException(e.ToString(), (Exception)e);
				}
				throw new JSchException(e.ToString());
			}
			NSch.KeyPair kpair = null;
			if (type == DSA)
			{
				kpair = new KeyPairDSA(jsch);
			}
			else
			{
				if (type == RSA)
				{
					kpair = new KeyPairRSA(jsch);
				}
			}
			if (kpair != null)
			{
				kpair.encrypted = encrypted;
				kpair.publickeyblob = publickeyblob;
				kpair.vendor = vendor;
				kpair.PublicKeyComment = PublicKeyComment;
				kpair.cipher = cipher;
				if (encrypted)
				{
					kpair.iv = iv;
					kpair.data = data;
				}
				else
				{
					if (kpair.Parse(data))
					{
						return kpair;
					}
					else
					{
						throw new JSchException("invalid privatekey: " + prvkey);
					}
				}
			}
			return kpair;
		}

		/// <exception cref="NSch.JSchException"/>
		public static NSch.KeyPair load(JSch jsch, byte[] prvkey, byte[] pubkey)
		{
			byte[] iv = new byte[8];
			// 8
			bool encrypted = true;
			byte[] data = null;
			byte[] publickeyblob = null;
			int type = ERROR;
			int vendor = VENDOR_OPENSSH;
			string PublicKeyComment = string.Empty;
			NSch.Cipher cipher = null;
			// prvkey from "ssh-add" command on the remote.
			if (pubkey == null && prvkey != null && (prvkey.Length > 11 && prvkey[0] == 0 && 
				prvkey[1] == 0 && prvkey[2] == 0 && (prvkey[3] == 7 || prvkey[3] == 19)))
			{
				Buffer buf = new Buffer(prvkey);
				buf.Skip(prvkey.Length);
				// for using Buffer#available()
				string _type = Sharpen.Runtime.GetStringForBytes(buf.GetString());
				// ssh-rsa or ssh-dss
				buf.Rewind();
				NSch.KeyPair kpair = null;
                if (_type.Equals("ssh-rsa"))
                {
                    kpair = KeyPairRSA.FromSSHAgent(jsch, buf);
                }
                else
				{
                    if (_type.Equals("ssh-dss"))
                    {
                        kpair = KeyPairDSA.FromSSHAgent(jsch, buf);
                    }
                    else
					{
                        if (_type.Equals("ecdsa-sha2-nistp256") || _type.Equals("ecdsa-sha2-nistp384") ||
                             _type.Equals("ecdsa-sha2-nistp512"))
                        {
                            kpair = KeyPairECDSA.FromSSHAgent(jsch, buf);
                        }
                        else
						{
							throw new JSchException("privatekey: invalid key " + Sharpen.Runtime.GetStringForBytes
								(prvkey, 4, 7));
						}
					}
				}
				return kpair;
			}
			try
			{
				byte[] buf = prvkey;
				if (buf != null)
				{
                    //NSch.KeyPair ppk = LoadPPK(jsch, buf);
                    //if (ppk != null)
                    //{
                    //    return ppk;
                    //}
				}
				int len = (buf != null ? buf.Length : 0);
				int i = 0;
				// skip garbage lines.
				while (i < len)
				{
					if (buf[i] == '-' && i + 4 < len && buf[i + 1] == '-' && buf[i + 2] == '-' && buf
						[i + 3] == '-' && buf[i + 4] == '-')
					{
						break;
					}
					i++;
				}
				while (i < len)
				{
					if (buf[i] == 'B' && i + 3 < len && buf[i + 1] == 'E' && buf[i + 2] == 'G' && buf
						[i + 3] == 'I')
					{
						i += 6;
						if (i + 2 >= len)
						{
							throw new JSchException("invalid privatekey: " + prvkey);
						}
						if (buf[i] == 'D' && buf[i + 1] == 'S' && buf[i + 2] == 'A')
						{
							type = DSA;
						}
						else
						{
							if (buf[i] == 'R' && buf[i + 1] == 'S' && buf[i + 2] == 'A')
							{
								type = RSA;
							}
							else
							{
								if (buf[i] == 'E' && buf[i + 1] == 'C')
								{
									type = ECDSA;
								}
								else
								{
									if (buf[i] == 'S' && buf[i + 1] == 'S' && buf[i + 2] == 'H')
									{
										// FSecure
										type = UNKNOWN;
										vendor = VENDOR_FSECURE;
									}
									else
									{
										if (i + 6 < len && buf[i] == 'P' && buf[i + 1] == 'R' && buf[i + 2] == 'I' && buf
											[i + 3] == 'V' && buf[i + 4] == 'A' && buf[i + 5] == 'T' && buf[i + 6] == 'E')
										{
											type = UNKNOWN;
											vendor = VENDOR_PKCS8;
											encrypted = false;
											i += 3;
										}
										else
										{
											if (i + 8 < len && buf[i] == 'E' && buf[i + 1] == 'N' && buf[i + 2] == 'C' && buf
												[i + 3] == 'R' && buf[i + 4] == 'Y' && buf[i + 5] == 'P' && buf[i + 6] == 'T' &&
												 buf[i + 7] == 'E' && buf[i + 8] == 'D')
											{
												type = UNKNOWN;
												vendor = VENDOR_PKCS8;
												i += 5;
											}
											else
											{
												throw new JSchException("invalid privatekey: " + prvkey);
											}
										}
									}
								}
							}
						}
						i += 3;
						continue;
					}
					if (buf[i] == 'A' && i + 7 < len && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf
						[i + 3] == '-' && buf[i + 4] == '2' && buf[i + 5] == '5' && buf[i + 6] == '6' &&
						 buf[i + 7] == '-')
					{
						i += 8;
						if (Session.CheckCipher((string)JSch.GetConfig("aes256-cbc")))
						{
							Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("aes256-cbc"));
							cipher = (NSch.Cipher)(System.Activator.CreateInstance(c));
							// key=new byte[cipher.getBlockSize()];
							iv = new byte[cipher.GetIVSize()];
						}
						else
						{
							throw new JSchException("privatekey: aes256-cbc is not available " + prvkey);
						}
						continue;
					}
					if (buf[i] == 'A' && i + 7 < len && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf
						[i + 3] == '-' && buf[i + 4] == '1' && buf[i + 5] == '9' && buf[i + 6] == '2' &&
						 buf[i + 7] == '-')
					{
						i += 8;
						if (Session.CheckCipher((string)JSch.GetConfig("aes192-cbc")))
						{
							Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("aes192-cbc"));
							cipher = (NSch.Cipher)(System.Activator.CreateInstance(c));
							// key=new byte[cipher.getBlockSize()];
							iv = new byte[cipher.GetIVSize()];
						}
						else
						{
							throw new JSchException("privatekey: aes192-cbc is not available " + prvkey);
						}
						continue;
					}
					if (buf[i] == 'A' && i + 7 < len && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf
						[i + 3] == '-' && buf[i + 4] == '1' && buf[i + 5] == '2' && buf[i + 6] == '8' &&
						 buf[i + 7] == '-')
					{
						i += 8;
						if (Session.CheckCipher((string)JSch.GetConfig("aes128-cbc")))
						{
							Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("aes128-cbc"));
							cipher = (NSch.Cipher)(System.Activator.CreateInstance(c));
							// key=new byte[cipher.getBlockSize()];
							iv = new byte[cipher.GetIVSize()];
						}
						else
						{
							throw new JSchException("privatekey: aes128-cbc is not available " + prvkey);
						}
						continue;
					}
					if (buf[i] == 'C' && i + 3 < len && buf[i + 1] == 'B' && buf[i + 2] == 'C' && buf
						[i + 3] == ',')
					{
						i += 4;
						for (int ii = 0; ii < iv.Length; ii++)
						{
							iv[ii] = unchecked((byte)(((A2b(buf[i++]) << 4) & unchecked((int)(0xf0))) + (A2b
								(buf[i++]) & unchecked((int)(0xf)))));
						}
						continue;
					}
					if (buf[i] == unchecked((int)(0x0d)) && i + 1 < buf.Length && buf[i + 1] == unchecked(
						(int)(0x0a)))
					{
						i++;
						continue;
					}
					if (buf[i] == unchecked((int)(0x0a)) && i + 1 < buf.Length)
					{
						if (buf[i + 1] == unchecked((int)(0x0a)))
						{
							i += 2;
							break;
						}
						if (buf[i + 1] == unchecked((int)(0x0d)) && i + 2 < buf.Length && buf[i + 2] == unchecked(
							(int)(0x0a)))
						{
							i += 3;
							break;
						}
						bool inheader = false;
						for (int j = i + 1; j < buf.Length; j++)
						{
							if (buf[j] == unchecked((int)(0x0a)))
							{
								break;
							}
							//if(buf[j]==0x0d) break;
							if (buf[j] == ':')
							{
								inheader = true;
								break;
							}
						}
						if (!inheader)
						{
							i++;
							if (vendor != VENDOR_PKCS8)
							{
								encrypted = false;
							}
							// no passphrase
							break;
						}
					}
					i++;
				}
				if (buf != null)
				{
					if (type == ERROR)
					{
						throw new JSchException("invalid privatekey: " + prvkey);
					}
					int start = i;
					while (i < len)
					{
						if (buf[i] == '-')
						{
							break;
						}
						i++;
					}
					if ((len - i) == 0 || (i - start) == 0)
					{
						throw new JSchException("invalid privatekey: " + prvkey);
					}
					// The content of 'buf' will be changed, so it should be copied.
					byte[] tmp = new byte[i - start];
					System.Array.Copy(buf, start, tmp, 0, tmp.Length);
					byte[] _buf = tmp;
					start = 0;
					i = 0;
					int _len = _buf.Length;
					while (i < _len)
					{
						if (_buf[i] == unchecked((int)(0x0a)))
						{
							bool xd = (_buf[i - 1] == unchecked((int)(0x0d)));
							// ignore 0x0a (or 0x0d0x0a)
							System.Array.Copy(_buf, i + 1, _buf, i - (xd ? 1 : 0), _len - (i + 1));
							if (xd)
							{
								_len--;
							}
							_len--;
							continue;
						}
						if (_buf[i] == '-')
						{
							break;
						}
						i++;
					}
					if (i - start > 0)
					{
						data = Util.FromBase64(_buf, start, i - start);
					}
					Util.Bzero(_buf);
				}
				if (data != null && data.Length > 4 && data[0] == unchecked((byte)0x3f) && data[
					1] == unchecked((byte)0x6f) && data[2] == unchecked((byte)0xf9) && data[3] == 
					unchecked((byte)0xeb))
				{
					// FSecure
					Buffer _buf = new Buffer(data);
					_buf.GetInt();
					// 0x3f6ff9be
					_buf.GetInt();
					byte[] _type = _buf.GetString();
					//System.err.println("type: "+new String(_type)); 
					string _cipher = Util.Byte2str(_buf.GetString());
					//System.err.println("cipher: "+_cipher); 
					if (_cipher.Equals("3des-cbc"))
					{
						_buf.GetInt();
						byte[] foo = new byte[data.Length - _buf.GetOffSet()];
						_buf.GetByte(foo);
						data = foo;
						encrypted = true;
						throw new JSchException("unknown privatekey format: " + prvkey);
					}
					else
					{
						if (_cipher.Equals("none"))
						{
							_buf.GetInt();
							_buf.GetInt();
							encrypted = false;
							byte[] foo = new byte[data.Length - _buf.GetOffSet()];
							_buf.GetByte(foo);
							data = foo;
						}
					}
				}
				if (pubkey != null)
				{
					try
					{
						buf = pubkey;
						len = buf.Length;
						if (buf.Length > 4 && buf[0] == '-' && buf[1] == '-' && buf[2] == '-' && buf[3] ==
							 '-')
						{
							// FSecure's public key
							bool valid = true;
							i = 0;
							do
							{
								i++;
							}
							while (buf.Length > i && buf[i] != unchecked((int)(0x0a)));
							if (buf.Length <= i)
							{
								valid = false;
							}
							while (valid)
							{
								if (buf[i] == unchecked((int)(0x0a)))
								{
									bool inheader = false;
									for (int j = i + 1; j < buf.Length; j++)
									{
										if (buf[j] == unchecked((int)(0x0a)))
										{
											break;
										}
										if (buf[j] == ':')
										{
											inheader = true;
											break;
										}
									}
									if (!inheader)
									{
										i++;
										break;
									}
								}
								i++;
							}
							if (buf.Length <= i)
							{
								valid = false;
							}
							int start = i;
							while (valid && i < len)
							{
								if (buf[i] == unchecked((int)(0x0a)))
								{
									System.Array.Copy(buf, i + 1, buf, i, len - i - 1);
									len--;
									continue;
								}
								if (buf[i] == '-')
								{
									break;
								}
								i++;
							}
							if (valid)
							{
								publickeyblob = Util.FromBase64(buf, start, i - start);
								if (prvkey == null || type == UNKNOWN)
								{
									if (publickeyblob[8] == 'd')
									{
										type = DSA;
									}
									else
									{
										if (publickeyblob[8] == 'r')
										{
											type = RSA;
										}
									}
								}
							}
						}
						else
						{
							if (buf[0] == 's' && buf[1] == 's' && buf[2] == 'h' && buf[3] == '-')
							{
								if (prvkey == null && buf.Length > 7)
								{
									if (buf[4] == 'd')
									{
										type = DSA;
									}
									else
									{
										if (buf[4] == 'r')
										{
											type = RSA;
										}
									}
								}
								i = 0;
								while (i < len)
								{
									if (buf[i] == ' ')
									{
										break;
									}
									i++;
								}
								i++;
								if (i < len)
								{
									int start = i;
									while (i < len)
									{
										if (buf[i] == ' ')
										{
											break;
										}
										i++;
									}
									publickeyblob = Util.FromBase64(buf, start, i - start);
								}
								if (i++ < len)
								{
									int start = i;
									while (i < len)
									{
										if (buf[i] == '\n')
										{
											break;
										}
										i++;
									}
									if (i > 0 && buf[i - 1] == unchecked((int)(0x0d)))
									{
										i--;
									}
									if (start < i)
									{
										PublicKeyComment = Sharpen.Runtime.GetStringForBytes(buf, start, i - start);
									}
								}
							}
							else
							{
								if (buf[0] == 'e' && buf[1] == 'c' && buf[2] == 'd' && buf[3] == 's')
								{
									if (prvkey == null && buf.Length > 7)
									{
										type = ECDSA;
									}
									i = 0;
									while (i < len)
									{
										if (buf[i] == ' ')
										{
											break;
										}
										i++;
									}
									i++;
									if (i < len)
									{
										int start = i;
										while (i < len)
										{
											if (buf[i] == ' ')
											{
												break;
											}
											i++;
										}
										publickeyblob = Util.FromBase64(buf, start, i - start);
									}
									if (i++ < len)
									{
										int start = i;
										while (i < len)
										{
											if (buf[i] == '\n')
											{
												break;
											}
											i++;
										}
										if (i > 0 && buf[i - 1] == unchecked((int)(0x0d)))
										{
											i--;
										}
										if (start < i)
										{
											PublicKeyComment = Sharpen.Runtime.GetStringForBytes(buf, start, i - start);
										}
									}
								}
							}
						}
					}
					catch (Exception)
					{
					}
				}
			}
			catch (Exception e)
			{
				if (e is JSchException)
				{
					throw (JSchException)e;
				}
				if (e is Exception)
				{
					throw new JSchException(e.ToString(), (Exception)e);
				}
				throw new JSchException(e.ToString());
			}
			NSch.KeyPair kpair_1 = null;
			if (type == DSA)
			{
				kpair_1 = new KeyPairDSA(jsch);
			}
			else
			{
				if (type == RSA)
				{
					kpair_1 = new KeyPairRSA(jsch);
				}
				else
				{
                    if (type == ECDSA)
                    {
                        kpair_1 = new KeyPairECDSA(jsch);
                    }
                    //else
                    //{
                    //    if (vendor == VENDOR_PKCS8)
                    //    {
                    //        kpair_1 = new KeyPairPKCS8(jsch);
                    //    }
                    //}
				}
			}
			if (kpair_1 != null)
			{
				kpair_1.encrypted = encrypted;
				kpair_1.publickeyblob = publickeyblob;
				kpair_1.vendor = vendor;
				kpair_1.PublicKeyComment = PublicKeyComment;
				kpair_1.cipher = cipher;
				if (encrypted)
				{
					kpair_1.encrypted = true;
					kpair_1.iv = iv;
					kpair_1.data = data;
				}
				else
				{
					if (kpair_1.Parse(data))
					{
						kpair_1.encrypted = false;
						return kpair_1;
					}
					else
					{
						throw new JSchException("invalid privatekey: " + prvkey);
					}
				}
			}
			return kpair_1;
		}

		private static byte A2b(byte c)
		{
			if ('0' <= c && ((sbyte)c) <= '9')
			{
				return unchecked((byte)(c - '0'));
			}
			return unchecked((byte)(c - 'a' + 10));
		}

		private static byte B2a(byte c)
		{
			if (0 <= c && ((sbyte)c) <= 9)
			{
				return unchecked((byte)(c + '0'));
			}
			return unchecked((byte)(c - 10 + 'A'));
		}

		public virtual void Dispose()
		{
			Util.Bzero(passphrase);
		}

		~KeyPair()
		{
			Dispose();
		}

		private static readonly string[] header1 = new string[] { "PuTTY-User-Key-File-2: "
			, "Encryption: ", "Comment: ", "Public-Lines: " };

		private static readonly string[] header2 = new string[] { "Private-Lines: " };

		private static readonly string[] header3 = new string[] { "Private-MAC: " };

		/// <exception cref="NSch.JSchException"/>
		internal static NSch.KeyPair loadPPK(JSch jsch, byte[] buf)
		{
			byte[] pubkey = null;
			byte[] prvkey = null;
			int lines = 0;
			Buffer buffer = new Buffer(buf);
			Hashtable v = new Hashtable();
			while (true)
			{
				if (!parseHeader(buffer, v))
				{
					break;
				}
			}
			string typ = (string)v["PuTTY-User-Key-File-2"];
			if (typ == null)
			{
				return null;
			}
			lines = System.Convert.ToInt32((string)v["Public-Lines"]);
			pubkey = parseLines(buffer, lines);
			while (true)
			{
				if (!parseHeader(buffer, v))
				{
					break;
				}
			}
			lines = System.Convert.ToInt32((string)v["Private-Lines"]);
			prvkey = parseLines(buffer, lines);
			while (true)
			{
				if (!parseHeader(buffer, v))
				{
					break;
				}
			}
			prvkey = Util.FromBase64(prvkey, 0, prvkey.Length);
			pubkey = Util.FromBase64(pubkey, 0, pubkey.Length);
			NSch.KeyPair kpair = null;
			if (typ.Equals("ssh-rsa"))
			{
				Buffer _buf = new Buffer(pubkey);
				_buf.Skip(pubkey.Length);
				int len = _buf.GetInt();
				_buf.GetByte(new byte[len]);
				// ssh-rsa
				byte[] pub_array = new byte[_buf.GetInt()];
				_buf.GetByte(pub_array);
				byte[] n_array = new byte[_buf.GetInt()];
				_buf.GetByte(n_array);
                kpair = new KeyPairRSA(jsch, n_array, pub_array, null);
			}
			else
			{
				if (typ.Equals("ssh-dss"))
				{
					Buffer _buf = new Buffer(pubkey);
					_buf.Skip(pubkey.Length);
					int len = _buf.GetInt();
					_buf.GetByte(new byte[len]);
					// ssh-dss
					byte[] p_array = new byte[_buf.GetInt()];
					_buf.GetByte(p_array);
					byte[] q_array = new byte[_buf.GetInt()];
					_buf.GetByte(q_array);
					byte[] g_array = new byte[_buf.GetInt()];
					_buf.GetByte(g_array);
					byte[] y_array = new byte[_buf.GetInt()];
					_buf.GetByte(y_array);
                    kpair = new KeyPairDSA(jsch, p_array, q_array, g_array, y_array, null);
				}
				else
				{
					return null;
				}
			}
			if (kpair == null)
			{
				return null;
			}
			kpair.encrypted = !v["Encryption"].Equals("none");
			kpair.vendor = VENDOR_PUTTY;
			kpair.PublicKeyComment = (string)v["Comment"];
			if (kpair.encrypted)
			{
                //if (Session.CheckCipher((string)JSch.GetConfig("aes256-cbc")))
                //{
                //    try
                //    {
                //        Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("aes256-cbc"));
                //        kpair.cipher = (NSch.Cipher)(System.Activator.CreateInstance(c));
                //        kpair.iv = new byte[kpair.cipher.GetIVSize()];
                //    }
                //    catch (Exception)
                //    {
                //        throw new JSchException("The cipher 'aes256-cbc' is required, but it is not available."
                //            );
                //    }
                //}
                //else
				{
					throw new JSchException("The cipher 'aes256-cbc' is required, but it is not available."
						);
				}
				kpair.data = prvkey;
			}
			else
			{
				kpair.data = prvkey;
				kpair.Parse(prvkey);
			}
			return kpair;
		}

		private static byte[] parseLines(Buffer buffer, int lines)
		{
			byte[] buf = buffer.buffer;
			int index = buffer.index;
			byte[] data = null;
			int i = index;
			while (lines-- > 0)
			{
				while (buf.Length > i)
				{
					if (buf[i++] == unchecked((int)(0x0d)))
					{
						if (data == null)
						{
							data = new byte[i - index - 1];
							System.Array.Copy(buf, index, data, 0, i - index - 1);
						}
						else
						{
							byte[] tmp = new byte[data.Length + i - index - 1];
							System.Array.Copy(data, 0, tmp, 0, data.Length);
							System.Array.Copy(buf, index, tmp, data.Length, i - index - 1);
							for (int j = 0; j < data.Length; j++)
							{
								data[j] = 0;
							}
							// clear
							data = tmp;
						}
						break;
					}
				}
				if (buf[i] == unchecked((int)(0x0a)))
				{
					i++;
				}
				index = i;
			}
			if (data != null)
			{
				buffer.index = index;
			}
			return data;
		}

		private static bool parseHeader(Buffer buffer, Hashtable v)
		{
			byte[] buf = buffer.buffer;
			int index = buffer.index;
			string key = null;
			string value = null;
			for (int i = index; i < buf.Length; i++)
			{
				if (buf[i] == unchecked((int)(0x0d)))
				{
					break;
				}
				if (buf[i] == ':')
				{
					key = Sharpen.Runtime.GetStringForBytes(buf, index, i - index);
					i++;
					if (i < buf.Length && buf[i] == ' ')
					{
						i++;
					}
					index = i;
					break;
				}
			}
			if (key == null)
			{
				return false;
			}
			for (int i_1 = index; i_1 < buf.Length; i_1++)
			{
				if (buf[i_1] == unchecked((int)(0x0d)))
				{
					value = Sharpen.Runtime.GetStringForBytes(buf, index, i_1 - index);
					i_1++;
					if (i_1 < buf.Length && buf[i_1] == unchecked((int)(0x0a)))
					{
						i_1++;
					}
					index = i_1;
					break;
				}
			}
			if (value != null)
			{
				v.Put(key, value);
				buffer.index = index;
			}
			return (key != null && value != null);
		}

		internal virtual void copy(NSch.KeyPair kpair)
		{
			this.publickeyblob = kpair.publickeyblob;
			this.vendor = kpair.vendor;
			this.PublicKeyComment = kpair.PublicKeyComment;
			this.cipher = kpair.cipher;
		}

		[System.Serializable]
		internal class ASN1Exception : Exception
		{
			internal ASN1Exception(KeyPair _enclosing)
			{
				this._enclosing = _enclosing;
			}

			private readonly KeyPair _enclosing;
		}

		internal class ASN1
		{
			internal byte[] buf;

			internal int start;

			internal int length;

			/// <exception cref="NSch.KeyPair.ASN1Exception"/>
            //internal ASN1(KeyPair _enclosing, byte[] buf)
            //    : this(buf, 0, buf.Length)
            //{
            //    this._enclosing = _enclosing;
            //}

			/// <exception cref="NSch.KeyPair.ASN1Exception"/>
			internal ASN1(KeyPair _enclosing, byte[] buf, int start, int length)
			{
				this._enclosing = _enclosing;
				this.buf = buf;
				this.start = start;
				this.length = length;
				if (start + length > buf.Length)
				{
                    //throw new NSch.KeyPair.ASN1Exception(this);
				}
			}

			internal virtual int getType()
			{
				return this.buf[this.start] & unchecked((int)(0xff));
			}

			internal virtual bool isSEQUENCE()
			{
				return this.getType() == (unchecked((int)(0x30)) & unchecked((int)(0xff)));
			}

			internal virtual bool isINTEGER()
			{
				return this.getType() == (unchecked((int)(0x02)) & unchecked((int)(0xff)));
			}

			internal virtual bool isOBJECT()
			{
				return this.getType() == (unchecked((int)(0x06)) & unchecked((int)(0xff)));
			}

			internal virtual bool isOCTETSTRING()
			{
				return this.getType() == (unchecked((int)(0x04)) & unchecked((int)(0xff)));
			}

			private int getLength(int[] indexp)
			{
				int index = indexp[0];
				int length = this.buf[index++] & unchecked((int)(0xff));
				if ((length & unchecked((int)(0x80))) != 0)
				{
					int foo = length & unchecked((int)(0x7f));
					length = 0;
					while (foo-- > 0)
					{
						length = (length << 8) + (this.buf[index++] & unchecked((int)(0xff)));
					}
				}
				indexp[0] = index;
				return length;
			}

			internal virtual byte[] getContent()
			{
				int[] indexp = new int[1];
				indexp[0] = this.start + 1;
				int length = this.getLength(indexp);
				int index = indexp[0];
				byte[] tmp = new byte[length];
				System.Array.Copy(this.buf, index, tmp, 0, tmp.Length);
				return tmp;
			}

			/// <exception cref="NSch.KeyPair.ASN1Exception"/>
			internal virtual NSch.KeyPair.ASN1[] getContents()
			{
				int typ = this.buf[this.start];
				int[] indexp = new int[1];
				indexp[0] = this.start + 1;
				int length = this.getLength(indexp);
				if (typ == unchecked((int)(0x05)))
				{
					return new NSch.KeyPair.ASN1[0];
				}
				int index = indexp[0];
				ArrayList values = new ArrayList();
				while (length > 0)
				{
					index++;
					length--;
					int tmp = index;
					indexp[0] = index;
					int l = this.getLength(indexp);
					index = indexp[0];
					length -= (index - tmp);
					values.Add(new NSch.KeyPair.ASN1(this._enclosing, this.buf, tmp - 1, 1 + (index -
						 tmp) + l));
					index += l;
					length -= l;
				}
				NSch.KeyPair.ASN1[] result = new NSch.KeyPair.ASN1[values.Count];
				for (int i = 0; i < values.Count; i++)
				{
					result[i] = (NSch.KeyPair.ASN1)values[i];
				}
				return result;
			}

			private readonly KeyPair _enclosing;
		}
	}
}
